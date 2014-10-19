import json
import socket
import sys

from twisted.internet import defer, endpoints, protocol, task
from twisted.names.client import getResolver
from twisted.names import dns
from twisted.python import log


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


class ProxyClientProtocol(protocol.Protocol):
    def __init__(self):
        self.peer = None
        self.peerBuffer = []
        self.earlyLoss = False

    def peerEstablished(self, peer):
        if self.earlyLoss:
            self.peer.transport.abortConnection()
            return
        self.peer = peer
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
        else:
            self.earlyLoss = True


class ProxyProtocol(protocol.Protocol):
    def __init__(self):
        self.client = None
        self.clientBuffer = []
        self.deferred = None

    def connectionMade(self):
        peer = self.transport.getPeer()
        ptrDeferred = self.factory.resolver.lookupPointer(reverseIP(peer.host))
        ptrDeferred.addCallback(extractPTR)
        ptrDeferred.addErrback(lambda ign: peer.host)
        clientDeferred = self.factory.clientEndpoint.connect(
            protocol.Factory.forProtocol(ProxyClientProtocol))
        self.deferred = defer.gatherResults(
            [ptrDeferred, clientDeferred], consumeErrors=True)
        self.deferred.addCallback(self._gotClient, peer.host)
        self.deferred.addErrback(self._noClient)

    def dataReceived(self, data):
        if self.client is not None:
            self.client.transport.write(data)
        else:
            self.clientBuffer.append(data)

    def _gotClient(self, result, address):
        hostname, self.client = result
        buf, self.clientBuffer = self.clientBuffer, None
        self.client.transport.write('WEBIRC %s cgiirc %s %s\r\n' % (
            self.factory.password, hostname, address))
        self.client.transport.writeSequence(buf)
        self.client.peerEstablished(self)

    def _noClient(self, reason):
        log.err(reason, 'connection failed from %r' % (self,))
        self.transport.abortConnection()

    def connectionLost(self, reason):
        if self.client:
            self.client.transport.loseConnection()
        elif self.deferred:
            self.deferred.cancel()


class ProxyFactory(protocol.Factory):
    protocol = ProxyProtocol

    def __init__(self, clientEndpoint, resolver, config):
        self.clientEndpoint = clientEndpoint
        self.resolver = resolver
        self.password = config['password'].encode()


def main(reactor, client, server, config):
    log.startLogging(sys.stdout)
    with open(config) as infile:
        config = json.load(infile)
    resolver = getResolver()
    client = endpoints.clientFromString(reactor, client)
    server = endpoints.serverFromString(reactor, server)
    d = server.listen(ProxyFactory(client, resolver, config))
    d.addCallback(lambda ign: defer.Deferred())
    return d


task.react(main, sys.argv[1:])
