import functools
import itertools
import socket
import sys

from twisted.application.internet import StreamServerEndpointService
from twisted.application.service import IServiceMaker, MultiService
from twisted.internet import defer, endpoints, protocol
from twisted.names.client import getResolver
from twisted.names import dns
from twisted.plugin import IPlugin
from twisted.python import log, usage
import yaml
from zope.interface import implementer


msg = functools.partial(log.msg, system='zangoose')
connectionCounter = itertools.count()


def reverseIPv4(address):
    tokens = list(reversed(address.split('.'))) + ['in-addr', 'arpa', '']
    return '.'.join(tokens)


def reverseIPv6(address):
    fullHex = ''.join('%02x' % (ord(c),)
                      for c in socket.inet_pton(socket.AF_INET6, address))
    tokens = list(reversed(fullHex)) + ['ip6', 'arpa', '']
    return '.'.join(tokens)


def reverseIP(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except socket.error:
        return reverseIPv6(address)
    else:
        return reverseIPv4(address)


def extractPTR(answer):
    answers, authority, additional = answer
    for rr in answers:
        if rr.type == dns.PTR:
            return str(rr.payload.name)
    raise ValueError('no PTR')


def maybeEnableKeepAlive(transport):
    meth = getattr(transport, 'setTcpKeepAlive', None)
    if meth is not None:
        meth(True)


class ProxyClientProtocol(protocol.Protocol):
    def __init__(self):
        self.peer = None
        self.peerBuffer = []
        self.earlyLoss = False

    def connectionMade(self):
        maybeEnableKeepAlive(self.transport)

    def peerEstablished(self, peer):
        if self.earlyLoss:
            self.peer.transport.abortConnection()
            return
        self.peer = peer
        msg('%s: client connection established to %s' % (
            self.peer.count, self.transport.getPeer()))
        buf, self.peerBuffer = self.peerBuffer, None
        self.peer.transport.writeSequence(buf)

    def dataReceived(self, data):
        if self.peer:
            self.peer.transport.write(data)
        else:
            self.peerBuffer.append(data)

    def connectionLost(self, reason):
        if self.peer:
            self.peer.transport.loseConnection()
            msg('%s: client connection lost to %s' % (
                self.peer.count, self.transport.getPeer()))
        else:
            self.earlyLoss = True


class ProxyProtocol(protocol.Protocol):
    def __init__(self):
        self.client = None
        self.clientBuffer = []
        self.deferred = None

    def connectionMade(self):
        maybeEnableKeepAlive(self.transport)
        self.count = next(connectionCounter)
        peer = self.transport.getPeer()
        msg('%s: connection established from %s' % (self.count, peer))
        if self.factory.password is not None:
            ptrDeferred = self.factory.resolver.lookupPointer(
                reverseIP(peer.host))
            ptrDeferred.addCallback(extractPTR)
            ptrDeferred.addErrback(lambda ign: peer.host)
        else:
            ptrDeferred = defer.succeed(None)
        clientDeferred = self.factory.clientEndpoint.connect(
            protocol.Factory.forProtocol(ProxyClientProtocol))
        self.deferred = defer.gatherResults(
            [ptrDeferred, clientDeferred], consumeErrors=True)
        self.deferred.addCallback(self._gotClient, peer.host)
        self.deferred.addErrback(self._noClient, peer)

    def dataReceived(self, data):
        if self.client is not None:
            self.client.transport.write(data)
        else:
            self.clientBuffer.append(data)

    def _gotClient(self, result, address):
        hostname, self.client = result
        buf, self.clientBuffer = self.clientBuffer, None
        if self.factory.password is not None:
            self.client.transport.write('WEBIRC %s cgiirc %s %s\r\n' % (
                self.factory.password, hostname, address))
        self.client.transport.writeSequence(buf)
        self.client.peerEstablished(self)

    def _noClient(self, reason, peer):
        log.err(reason, '%s: client connection failed from %s' % (
            self.count, peer))
        self.transport.abortConnection()

    def connectionLost(self, reason):
        msg('%s: connection lost from %s' % (
            self.count, self.transport.getPeer()))
        if self.client:
            self.client.transport.loseConnection()
        elif self.deferred:
            self.deferred.cancel()


class ProxyFactory(protocol.Factory):
    protocol = ProxyProtocol

    def __init__(self, clientEndpoint, resolver, config):
        self.clientEndpoint = clientEndpoint
        self.resolver = resolver
        self.password = None
        if 'cgiirc' in config:
            self.password = str(config['cgiirc'])


class ZangooseOptions(usage.Options):
    def parseArgs(self, *args):
        if len(args) == 1:
            self.config, = args
        else:
            self.opt_help()

    def getSynopsis(self):
        return 'Usage: twistd [options] zangoose <config file>'


@implementer(IServiceMaker, IPlugin)
class ZangooseServiceMaker(object):
    tapname = 'zangoose'
    description = 'A flexible proxy server.'
    options = ZangooseOptions
    reactor = resolver = None

    def makeService(self, options):
        reactor = self.reactor
        if reactor is None:
            from twisted.internet import reactor

        resolver = self.resolver
        if resolver is None:
            resolver = getResolver()

        with open(options.config) as infile:
            config = yaml.safe_load(infile)

        multiService = MultiService()

        for proxy in config['proxies']:
            client = endpoints.clientFromString(reactor, str(proxy['client']))
            server = endpoints.serverFromString(reactor, str(proxy['server']))
            fac = ProxyFactory(client, resolver, proxy)
            service = StreamServerEndpointService(server, fac)
            service.setServiceParent(multiService)

        return multiService


def logger():
    parent = log.FileLogObserver(sys.stdout)

    def observer(event):
        if event['isError'] or event.get('system') == 'zangoose':
            parent.emit(event)

    return observer
