"""
The error module provides basic support for error reporting and
error handling for PLAYGROUND. This module contains elements that
are common to the entire system. Individual sub-modules should contain
their own error subclasses.
"""

import Common
from Common import PlaygroundError
from ErrorHandler import ErrorLevel, ErrorHandler, GetErrorReporter, LoggingErrorHandler, SimpleDebugErrorHandler