'''
Created on Oct 22, 2013

@author: sethjn
'''

class NetworkMessageException(Exception):
    """
    This class is purely for convenience in trapping exceptions.
    All errors reported from messages classes should return 
    errors of this type, so they can be easily identified and
    trapped.
    """ 

class ValidationResult(object):
    """
    A big part of working with message construction, serialization,
    deserialization, and so forth is the validation of the data.
    All of the "validate" methods associated with these classes 
    returns a ValidationResult that can be treated as a boolean
    (true if successful, false if failure) and includes a related
    message."""
    
    def __init__(self, success, msg):
        self.success = success
        self.msg = msg
        
    def __nonzero__(self):
        return self.success
    
    def __str__(self):
        return "Validation " + (self.success and "OK" or "Failed") + ": " + self.msg
        
class Validated(ValidationResult):
    """
    Convenience class for created a ValidationResult that
    represents a successful validation. Most validation methods
    that succeeded can simply return Validated()
    """
    
    def __init__(self, msg="Validation successful"):
        ValidationResult.__init__(self, True, msg)
        
class ValidationFailure(ValidationResult, NetworkMessageException):
    """
    This class represents a validation failure that can be returned,
    but it also inherits from NetworkMessageException so it can be
    raised if necessary.
    """
    def __init__(self, msg):
        ValidationResult.__init__(self, False, msg)
        Exception.__init__(self, msg)
        
class MissingValue(ValidationFailure):
    """
    This failure should be returned from a validation() when a 
    required value is missing.
    """
    def __init__(self):
        ValidationFailure.__init__(self, "Required value not set")
        
class FieldError(ValidationFailure):
    """
    This class is used when a specific field has an error.
    """
    def __init__(self, fieldName, originalError):
        ValidationFailure.__init__(self, "Error in field [%s]: %s" % (fieldName, str(originalError)))
        self.fieldName = fieldName
        self.originalError = originalError
        
class DuplicateTag(Exception):
    """
    This class is used when a field is assigned a duplicate tag.
    """
    def __init__(self, fieldName1, fieldName2, tag):
        Exception.__init__(self, "Attempt to give [%s] tag %d already claimed by [%s]" % (fieldName1, tag, fieldName2))

class OutOfBounds(ValidationFailure):
    """
    This failure should be returned from a validation() when a 
    value is out of the range of legal values.
    """
    def __init__(self, min, max, value):
        if value < min: ValidationFailure.__init__(self, str(value) + " is less than " + str(min))
        else: ValidationFailure.__init__(self, str(value) + " is greater than " + str(max))
        self.min = min
        self.max = max
        self.value = value
        
class InvalidValue(ValidationFailure):
    """
    This failure should be returned from a valaidation() when a
    value is not valid (e.g., not in enum)
    """
    def __init__(self, value, validValues):
        ValidationFailure.__init__(self, str(value) + " is not in the valid set " + str(validValues))
        self.value = value
        self.validValues = validValues

class InvalidLength(ValidationFailure):
    """
    This failure should be returned from validate() when a
    value is of an incorrect size.
    """
    def __init__(self, fixedLen, listLen):
        Exception.__init__(self, "Expected list of length %d but had list of length %d" % (fixedLen, listLen))

class InvalidData(NetworkMessageException):
    """
    This exception can be raised anytime the wrong type of data is
    used in a message. Passing a floating point when an integer is 
    expected, for example, should raise this type of Error.
    """

class InvalidSymbolInScope(NetworkMessageException):
    """
    This exception is raised when a keyed message definition
    uses an unknown symbol.
    """
    
class InvalidProtocolDefinition(NetworkMessageException):
    """
    This exception is raised when an unknown protocol message
    is requested.
    """
    
class DeserializationError(NetworkMessageException):
    """
    This execption is raised when deserialization throws an error
    """
    def __init__(self, e, msg, partialMsgHandler):
        Exception.__init__(self, msg)
        self.e = e
        self.msgHandler = partialMsgHandler
        
class UnexpectedMessageError(NetworkMessageException):
    """
    This exception is raised when a message is received, but of the wrong type
    """