from playground.twisted import endpoints
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

class DumpProtocol(Protocol):
    def dataReceived(self, data):
        print "TAP received %d bytes from %s to %s" % (len(data), self.transport.getPeer(), self.transport.getHost())

class DumpFactory(Factory):
    protocol = DumpProtocol

def tap(address, port, gateTcpPort=9091):
    settings = endpoints.PlaygroundNetworkSettings()
    settings.changeGate(gateTcpPort=gateTcpPort)
    settings.requestSpecificAddress(address)

    tap = endpoints.GateServerEndpoint(reactor, port, settings)

    protocolFactory = DumpFactory()

    tap.listen(protocolFactory)

if __name__=="__main__":
    import sys
    gstarArgs = {}

    args = sys.argv[1:]
    i = 0
    for arg in args:
        if arg.startswith("-"):
            k,v = arg.split("=")
            gstarArgs[k]=v
        else:
            gstarArgs[i] = arg
            i+=1
    
    
    gatePort = gstarArgs.get("--gate-port", default=9091)
    tapAddress, tapPort = gstarArgs[0], int(gstarArgs[1])

    print "Starting simple playground 'wiretap'"
    tap(tapAddress, tapPort, gateTcpPort=gate_port)
    reactor.run()
