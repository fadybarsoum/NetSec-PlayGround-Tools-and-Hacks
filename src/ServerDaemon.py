'''
Created on Jan 14, 2014

@author: sethjn
'''

import sys, os, time
import playground

k_MIN_TCP_PORT = 1024
k_MAX_TCP_PORT = 49151
k_MIN_TIME_FOR_SUCCESSFUL_RUN = 30.0
k_MAX_FAILED_RUNS = 10
k_USAGE = """
USAGE: ServerDaemon <port> <mode>
\tport: integer between %d and %d
\tmode: one of "once" or "daemon"

If ServerDaemon is launched in daemon mode, the server
will be restarted if it stops. However, if it stops in 
a short period of time (%d seconds) %d consecutive times
in a row, the daemon will exit.
""" % (k_MIN_TCP_PORT, k_MAX_TCP_PORT, k_MIN_TIME_FOR_SUCCESSFUL_RUN, k_MAX_FAILED_RUNS)

def main(args):
    if len(args) < 3:
        raise Exception("Wrong number of arguments.%s" % k_USAGE)
    progname = args[0]
    port = args[1]
    mode = args[2]
    
    try:
        port = int(port)
    except:
        raise Exception("Invalid argument '%s' for port.%s" % (args[1], k_USAGE))
    
    if port < k_MIN_TCP_PORT or port > k_MAX_TCP_PORT:
        raise Exception("Port out of range. Must fall between %d and %d" % (k_MIN_TCP_PORT, k_MAX_TCP_PORT))
    
    if mode == "once":
        server = playground.network.server.PlaygroundServer('localhost', port)
        server.run()
    elif mode == "daemon":
        failedCount = 0
        while True:
            starttime = time.time()
            print("Launching daemon.")
            os.system("python %s %d once" % (progname, port))
            endtime = time.time()
            runtime = endtime - starttime
            if runtime < k_MIN_TIME_FOR_SUCCESSFUL_RUN:
                failedCount += 1
                print("Daemon failed: Consecutive failures now %d" % failedCount)
            else:
                failedCount = 0
            if failedCount >= k_MAX_FAILED_RUNS:
                raise Exception("Too many failures; Daemon exiting.")
    else:
        raise Exception("Invalid argument '%s' for mode.%s" % (args[2], k_USAGE))
    
    return 0

if __name__ == "__main__":
    try:
        returnCode = main(sys.argv)
    except Exception, e:
        print("Error launching server.")
        print(e)
        returnCode = -1
    sys.exit(returnCode)