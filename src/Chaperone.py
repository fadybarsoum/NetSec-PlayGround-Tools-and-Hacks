'''
Created on Jan 14, 2014

@author: sethjn
'''

import sys, os, time, argparse
import playground

k_MIN_TCP_PORT = 1024
k_MAX_TCP_PORT = 49151
k_MIN_TIME_FOR_SUCCESSFUL_RUN = 30.0
k_MAX_FAILED_RUNS = 10

K_CUSTOM_USAGE = (
"""
\t%(prog)s (--help | -h)
\t%(prog)s [shutdown options]
\t%(prog)s [launch options]"""
                  )

def errorRateStringTuple(errorRateString):
    errorRateTuple = map(int, errorRateString.split(","))
    if len(errorRateTuple) != 3:
        raise Exception("Rate must be in the form of lo,hi,denominator")
    return errorRateTuple

cliHandler = argparse.ArgumentParser(description=(
"""The Chaperone is a special server that makes the Playground System
work. All Playground nodes connect to the Chaperone which provides
the Playground connectivity substrate. Playground nodes have a Playground
address with the Chaperone. Messages sent to that address are routed
by the Chaperone to the appropriate node(s)."""),
                                    epilog=(
"""errorRate and lossRate must be written as a no-whitespace,
comma-separated triple lo,hi,denominator (e.g., 1,10,1000).
This represents the lowest and highest fraction of 
error. So, 1,10,1000 says a minimum of 1 error in every 1000
packets and a maximum of 10 errors in every 1000 packets.
Recommended values for error is 1,10,10000 and for loss is
1,5,100.

Daemon mode will attempt to detect an inherently defective
Chaperone. If it shuts down too quickly (< %d seconds)
more than %d consecutive times, the daemon will exit.
""" % (k_MIN_TIME_FOR_SUCCESSFUL_RUN,
                                                            k_MAX_FAILED_RUNS)),
                                     usage = K_CUSTOM_USAGE,
                                     )

normalOptionsGroup = cliHandler.add_argument_group("Launch Options",
                                                   "Options for launching the Chaperone")
normalOptionsGroup.add_argument("-p","--port",
                        default=9090,
                        type=int,
                        help="Port for playground node connections.")
normalOptionsGroup.add_argument("--daemon",
                        default=False,
                        action="store_true",
                        help="Run Chaperone in daemon mode, restarting if it dies.")
normalOptionsGroup.add_argument("--error_rate",
                        default=None,
                        type=errorRateStringTuple,
                        help="The rate of errors in packets")
normalOptionsGroup.add_argument("--loss_rate",
                        default=None,
                        type=errorRateStringTuple,
                        help="The rate of dropped packets")
shutdownGroup = cliHandler.add_argument_group("Shutdown Options","Options for stopping a daemon")
shutdownGroup.add_argument("--killAll",
                           default=False,
                           action="store_true",
                           help="Kill all daemons and running instances of Chaperone")

def main(args):
    config = cliHandler.parse_args(args[1:])
    config.progName = args[0]
    print config
    
    if config.killAll:
        os.system("pkill -f " + config.progName)
        return 0
    
    port = config.port
    
    if port < k_MIN_TCP_PORT or port > k_MAX_TCP_PORT:
        raise Exception("Port out of range. Must fall between %d and %d" % (k_MIN_TCP_PORT, k_MAX_TCP_PORT))
    
    if not config.daemon:
        server = playground.network.server.PlaygroundServer('localhost', port)
        if config.error_rate:
            server.setNetworkErrorRate(*config.error_rate)
        if config.loss_rate:
            server.setNetworkLossRate(*config.loss_rate)
        server.run()
    else:
        failedCount = 0
        while True:
            starttime = time.time()
            print("Dameon launching %s instance" % config.progName)
            pgcommand = "python %s" % config.progName
            pgcommand += " --port=%d" % config.port
            if config.error_rate:
                pgcommand += " --error_rate=" + ",".join(map(str,config.error_rate))
            if config.loss_rate:
                pgcommand += " --loss_rate=" + ",".join(map(str,config.loss_rate))
            print("\tcommand: " + pgcommand)
            os.system(pgcommand)
            endtime = time.time()
            runtime = endtime - starttime
            if runtime < k_MIN_TIME_FOR_SUCCESSFUL_RUN:
                failedCount += 1
                print("Daemon failed: Consecutive failures now %d" % failedCount)
            else:
                failedCount = 0
            if failedCount >= k_MAX_FAILED_RUNS:
                raise Exception("Too many consecutive failures; Daemon exiting.")
    
    return 0

if __name__ == "__main__":
    try:
        returnCode = main(sys.argv)
    except Exception, e:
        print("Error launching Chaperone.")
        print(e)
        returnCode = -1
    sys.exit(returnCode)
