'''
Created on Oct 18, 2013

@author: sethjn
'''
import struct, random
from Errors import *

def getStreamBuffer(offset, bufs, requiredSize):
    if not bufs:
        # offset is local to the buffer. Reset to 0 
        return (False, 0)
    while (len(bufs[0])-offset) < requiredSize:
        if len(bufs) == 1:
            return (False, offset)
        curBuf = bufs.pop(0)
        bufs[0] = curBuf[offset:] + bufs[0]
        # reset local offset to 0
        offset = 0
    return (True, offset)

def getStreamUnpack(offset, bufs, packCode):
    unpackSize = struct.calcsize(packCode)
    bigEnough, offset = getStreamBuffer(offset, bufs, unpackSize)
    if not bigEnough:
        return (None, offset)
    else: 
        unpackedData = struct.unpack_from(packCode, bufs[0], offset)[0]
        return (unpackedData, offset+unpackSize)
    
def trimStream(bufs, offset):
    if not bufs:
        return 0
    else:
        bufs[0] = bufs[0][offset:]
        if not bufs[0]: bufs.pop(0)
        return 0

class ProtoFieldValue(object):
    """
    This is the core class for handling a piece of data in a network
    message. Every element in a message is a "protocol field" and
    this class represents the value of a field. Please note, however,
    it does not include information about the field itself (name, tag, etc.).
    
    Every ProtoFieldValue can return its "raw" data through data(). If no data
    is set, it returns ProtoFieldValue.UNSET.
    
    Every ProtoFieldValue can also serialize and deserialize itself.
    
    Values can have attributes. A subset of these provide additional 
    validation requirements on the value.
    
    Note that it is expected that all ProtoFieldValue's can be constructed
    without parameters. ProtoFieldValue classes are used in the definition
    of a message and must not require the constructing builders to have
    to figure out what to pass to the constructors.
    If parameters are required, they should be curried
    with a lambda or some similar pattern. 
    """
    
    UNSET = object()
    
    def __init__(self):
        self._data = self.UNSET
        self.__attributes = set([])
        self.__validators = []
        
    def data(self): return self._data
    
    def registerAttribute(self, attr):
        self.__attributes.add(attr)
        if isinstance(attr, ProtoFieldValidator):
            self.__validators.append(attr)
            
    def hasAttribute(self, attr):
        return attr in self.__attributes
    
    def getAttributesOfType(self, attrClass):
        results = []
        for attr in self.__attributes:
            if isinstance(attr, attrClass):
                results.append(attr)
        return results
        
    def validate(self):
        for v in self.__validators:
            vCheck = v.validate(self)
            if not vCheck: return vCheck
        return Validated()
    
    def serialize(self):
        return ""
    
    def deserialize(self, buf, offset=0):
        """
        The deserialize method will load data into
        the field from a buffer at an offset. It needs
        to return how many bytes of the buffer it
        consumed.
        """
        return 0
    
    def deserializeStream(self, bufs):
        yield None
    
class BasicFieldValue(ProtoFieldValue):
    """
    This class represents the most common "basic" or intrinsic
    types. It can handle any kind of data that has a corresponding
    code for packing a Python "struct".
    
    Because this class requires a parameter to indicate the type
    of value, it provides a staticmethod "DefineConcreteType" that
    curries the structure argument creating a parameter-less factory
    that can be used in place of the normal parameterized one.
    """
    
    @staticmethod
    def DefineConcreteType(structCode):
        """
        Create a parameterless factory of this class with
        the appropriate struct code.
        """
        return lambda: BasicFieldValue(structCode)
    
    def __init__(self, structCode):
        """
        The constructor will return an InvalidData exception
        if it is passed a structCode that cannot be processed
        by struct.calcsize()
        """
        ProtoFieldValue.__init__(self)
        structCode = "!"+structCode
        try:
            struct.calcsize(structCode)
        except struct.error, e:
            raise InvalidData("Unknown 'struct' character code [%s]" % structCode)
        self.__code = structCode
        
    def setData(self, newValue):
        """
        Set the data for this concrete type. This method throws
        an Invalid Data exception if it cannot be "packed" by the
        Python struct module.
        """
        try:
            struct.pack(self.__code, newValue)
        except struct.error, e:
            raise InvalidData("Terminal does not have appropriate type of data")
        self._data = newValue
        
    def serialize(self):
        return struct.pack(self.__code, self._data)
    
    def deserialize(self, buf, offset=0):
        self._data = struct.unpack_from(self.__code, buf, offset)[0]
        return struct.calcsize(self.__code)
    
    def deserializeStream(self, bufs):
        (data, offset) = getStreamUnpack(0, bufs, self.__code)
        while data == None:
            yield None
            (data, offset) = getStreamUnpack(offset, bufs, self.__code)
        self._data = data
        trimStream(bufs, offset)
        yield data
    
class StringFieldValue(ProtoFieldValue):
    """
    This is the only basic type that needs its own class because the
    struct string requires a size.
    """
    
    LENGTH_CODE = "I"
    STRING_CODE = "%ds"
    STRUCT_CODE = "!"+LENGTH_CODE+STRING_CODE
    MAX_SIZE = (2**32)-1
    
    def setData(self, newValue):
        self._data = str(newValue)
        if len(self._data) > self.MAX_SIZE:
            # Fail safely
            self._data = self.UNSET
            raise InvalidData("String length too long for string field. Maximum size is %d" % (self.MAX_SIZE))
        
    def serialize(self):
        return struct.pack(self.STRUCT_CODE%len(self._data), len(self._data), self._data)
    
    def deserialize(self, buf, offset):
        dataLen = struct.unpack_from("!"+self.LENGTH_CODE, buf, offset)[0]
        offset += struct.calcsize("!"+self.LENGTH_CODE)
        self._data = struct.unpack_from("!"+self.STRING_CODE%dataLen, buf, offset)[0]
        return struct.calcsize(self.STRUCT_CODE%dataLen)
    
    def deserializeStream(self, bufs):
        (dataLen, offset) = getStreamUnpack(0, bufs, "!"+self.LENGTH_CODE)
        while dataLen == None:
            yield None
            (dataLen, offset) = getStreamUnpack(offset, bufs, "!"+self.LENGTH_CODE)
        (stringVal, offset) = getStreamUnpack(offset, bufs, "!"+self.STRING_CODE%dataLen)
        while stringVal == None:
            yield None
            (stringVal, offset) = getStreamUnpack(offset, bufs, "!"+self.STRING_CODE%dataLen)
        self._data = stringVal
        trimStream(bufs, offset)   
        yield stringVal

class ListFieldValue(ProtoFieldValue):
    """
    A ListFieldValue is parameterized by some other type. For example,
    you can have a ListFieldValue(BasicFieldValue('H')) to create a list
    of unsigned short integers.
    
    Calling "data()" on the list will return a list with recursively 
    resolved elements (each element in the list will be the data() call
    on the corresponding element in the ListFieldValue). UNSET elements
    will not be included, so the length of a ListFieldValue is not
    necessarily the length of its data. However, all elements are serialized,
    so this is not a generally "good" thing to do.
    
    A list must be initialized or it remains UNSET. Initialization occurs
    by calling "init()" (which creates an empty list) or by adding at 
    least one element using "add()". Note that you can call init() followed
    by add() but it is unnecessary.
    
    When adding elements, the add method only creates the appropriate field,
    but does not fill it with data. To set data in a list, you access
    the appropriate element and then call setter methods on the element. If,
    for example, it was a list of short integers (BasicFieldType), after
    adding an element (to say, position 0), you would call 
    
    list[0].set(3)
    
    When a list is serialized, the list count is first serialized. The size
    is stored in an unsigned short, so this limits the number of list
    elements to about 65536.
    """
    
    class TypedListFactory(object):
        def __init__(self, elementType):
            self.elementType = elementType
        def __call__(self):
            return ListFieldValue(self.elementType)
        def __eq__(self, other):
            return isinstance(other, ListFieldValue.TypedListFactory) and other.elementType == self.elementType
    
    @staticmethod
    def DefineConcreteType(elementType):
        return ListFieldValue.TypedListFactory(elementType)
    
    LENGTH_STRUCT_CODE = "H"
    MAX_LENGTH = 65536  # Cannot find this constant in Python... bascially, USHRT_MAX
    
    def __init__(self, elementType):
        ProtoFieldValue.__init__(self)
        self.__type = elementType
        
    def __serializeListLength(self):
        return struct.pack("!"+self.LENGTH_STRUCT_CODE, len(self._data))
    
    def __deserializeListLength(self, buffer, offset=0):
        listLen = struct.unpack_from("!"+self.LENGTH_STRUCT_CODE, buffer, offset)[0]
        return (listLen, struct.calcsize("!"+self.LENGTH_STRUCT_CODE))
        
    def init(self):
        self._data = []
        
    def setData(self, rawList):
        self.init()
        for dataElm in rawList:
            self._data.append(self.__type())
            self._data[-1].setData(dataElm)
        
    def add(self, elementCount=1):
        """
        Adds elements to the list. The elements will be
        of the appropriate type, but will have their
        data UNSET
        """
        if elementCount < 0:
            raise NetworkMessageException("ListFieldElement.add requires an elementCount of 1 or greater")
        if self._data == self.UNSET:
            self.init()
        for x in range(elementCount):
            newElement = self.__type()
            self._data.append(newElement)
            
    def data(self):
        if self._data == self.UNSET: return self._data
        
        rawData = []
        for elm in self._data:
            rawElm = elm.data()
            if rawElm != elm.UNSET:
                rawData.append(rawElm)
        return rawData
            
    def __getitem__(self, key):
        return self._data[key]
    
    def __len__(self):
        return len(self._data)
    
    def serialize(self):
        buf = self.__serializeListLength()
        for elm in self._data:
            buf += elm.serialize()
        return buf
    
    def deserialize(self, buf, offset=0):
        listSize, listOffset = self.__deserializeListLength(buf, offset)
        self.add(listSize)
        for elm in range(listSize):
            listOffset += self._data[elm].deserialize(buf, offset+listOffset)
        return listOffset
    
    def deserializeStream(self, bufs):
        (listSize, offset) = getStreamUnpack(0, bufs, "!"+self.LENGTH_STRUCT_CODE)
        while listSize == None:
            yield None
            (listSize, offset) = getStreamUnpack(offset, bufs, self.__code)
        self.add(listSize)
        trimStream(bufs, offset)
        for elm in range(listSize):
            streamIterator = self._data[elm].deserializeStream(bufs)
            while streamIterator.next() == None:
                yield None  
        yield self._data
    
class ProtoFieldAttribute(object):
    """
    This class is currently empty and used only for typing.
    
    TODO: It may make sense to move attributes and validators
    off the values on onto the fields themselves. Think about it.
    """
    pass

class Initializer(ProtoFieldAttribute):
    """
    This class represents attributes that should operate on the 
    field at the time of instantiation but before any values are
    explicitly set.
    """
    def initialize(self, fieldValue):
        pass

class DefaultValue(Initializer):
    """ 
    Default value for a field
    """
    def getDefaultValue(self):
        None
        
    def initialize(self, field):
        field.setData(self.getDefaultValue())
    
class ExplicitDefaultValue(DefaultValue):
    """
    An explicit default value for a field. No guarantee
    that it will be the right type. Other validators ensure this
    """
    def __init__(self, value):
        self.value = value
        
    def getDefaultValue(self):
        return self.value
    
class RandomDefaultValue(DefaultValue):
    """
    Allows a field to be initialized with a random integer.
    
    TODO: instead of bytecount, could we put in UINT8 or something
    to allow it to go wider than integers?
    """
    def __init__(self, byteCount):
        self.byteCount = byteCount
        
    def getDefaultValue(self):
        """
        A new value is generated every time. However, this 
        should be ok as it should only be called once. 
        
        TODO: Is this for sure? Do we need to guarantee this?
        """
        return random.getrandbits(8*self.byteCount)

class ProtoFieldValidator(ProtoFieldAttribute):
    """
    A subclass of ProtoFieldAttribute that ProtoFieldValues
    will use in validation.
    """
    def validate(self, fieldValue):
        return Validated()
    
class RequiredAttribute(ProtoFieldValidator):
    """
    Values with this attribute must be set.
    """
    def validate(self, fieldValue):
        if fieldValue.data() == fieldValue.UNSET:
            return MissingValue()
        return Validated()
        
class Bounded(ProtoFieldValidator):
    """
    Values with this attribute must fall within the specified range
    """
    def __init__(self, min=None, max=None):
        self.min = min
        self.max = max
    def validate(self, fieldValue):
        if fieldValue.data() == fieldValue.UNSET: return Validated()
        if (self.min != None and fieldValue.data() < self.min) or (self.max != None and fieldValue.data() > self.max):
            return OutOfBounds(self.min, self.max, fieldValue.data())
        return Validated()
        
class FixedSize(ProtoFieldValidator):
    """
    This currently applies only to lists, but it could apply to strings as well.
    It fixes the size of the specified value for validation to be successful.
    """
    def __init__(self, fixedLen):
        self.fixedLen = fixedLen
    def validate(self, fieldValue):
        # this is a programming error, so we raise ,rather than return, this error
        if not isinstance(fieldValue, ListFieldValue): raise ValidationFailure("Fixedsize attribute only applies to list elements")
        
        if fieldValue.data() == fieldValue.UNSET: return Validated()
        if len(fieldValue.data()) != self.fixedLen:
            return InvalidLength(self.fixedLen, len(fieldValue.data()))
        return Validated()