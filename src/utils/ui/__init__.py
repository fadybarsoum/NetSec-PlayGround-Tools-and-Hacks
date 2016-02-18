from CLIShell import CLIShell
import platform
if platform.system().lower() == "windows":
    from twisted.internet import stdio
else:
    from twisted.internet import stdio as basic_stdio
    from CLIShell import TwistedStdioReplacement as stdio