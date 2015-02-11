'''
Created on Oct 22, 2013

@author: sethjn
'''

from ProtoFieldBuilder import *

"""
The following type constants are used for defining protocols.
These are names that map to python struct definition strings.
But hopefully, these names are far more expressive and 
meaningful.
"""
BOOL1 = BasicFieldValue.DefineConcreteType("?")

INT1 = BasicFieldValue.DefineConcreteType("b")
INT2 = BasicFieldValue.DefineConcreteType("h")
INT4 = BasicFieldValue.DefineConcreteType("i")
INT8 = BasicFieldValue.DefineConcreteType("q")

UINT1 = BasicFieldValue.DefineConcreteType("B")
UINT2 = BasicFieldValue.DefineConcreteType("H")
UINT4 = BasicFieldValue.DefineConcreteType("I")
UINT8 = BasicFieldValue.DefineConcreteType("Q")

FLOAT4 = BasicFieldValue.DefineConcreteType("f")
DOUBLE8 = BasicFieldValue.DefineConcreteType("d")

STRING = StringFieldValue

# OPTIONAL and REQURED can be used as a constant for normal fields
# And as a decorator for internal classes.
OPTIONAL = ProtoFieldAttribute()
REQUIRED = RequiredAttribute()

# Initializers
DEFAULT_VALUE = ExplicitDefaultValue
DEFAULT_RANDOM1 = RandomDefaultValue(1)
DEFAULT_RANDOM2 = RandomDefaultValue(2)
DEFAULT_RANDOM4 = RandomDefaultValue(4)
DEFAULT_RANDOM8 = RandomDefaultValue(8)

LIST = ListFieldValue.DefineConcreteType