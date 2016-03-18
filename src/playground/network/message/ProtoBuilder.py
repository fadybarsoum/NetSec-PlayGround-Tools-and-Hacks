'''
Created on Oct 18, 2013

@author: sethjn
'''

from ProtoFieldBuilder import *
from StandardMessageSpecifiers import OPTIONAL, REQUIRED, UINT8, DEFAULT_RANDOM8
from Errors import *
import traceback

def resolveDottedKey(dottedKey, toplevelDictionary):
    """
    Helper function that resolves dotted keys (x.a.b.c)
    """
    directoryKeys = dottedKey.split(".")
    directory = toplevelDictionary
    
    if not directoryKeys: return None
    
    for k in directoryKeys[:-1]:
        directory = directory.get(k, None)
        if type(directory) != type({}):
            return None
    return directory.get(directoryKeys[-1], None)
    
def storeDottedKey(dottedKey, toplevelDictionary, value):
    """
    Helper function that stores in recursive dictionaries using dotted keys (x.a.b.c)
    """
    directoryKeys = dottedKey.split(".")
    directory = toplevelDictionary
    
    if not directoryKeys: raise InvalidSymbolInScope("Cannot store a value to an empty key")
    
    for k in directoryKeys[:-1]:
        if not k:
            raise InvalidSymbolInScope("An individual key in a dotted key cannot be empty")
        if not directory.has_key(k):
            directory[k] = {}
        directory = directory[k]
    directory[directoryKeys[-1]] = value
    
def hasDottedKey(dottedKey, toplevelDictionary):
    """
    Helper function that resolves dotted keys (x.a.b.c)
    """
    if resolveDottedKey(dottedKey, toplevelDictionary) != None:
        return True
    return False

class MessageDefinitionMetaClass(type):
    """
    This meta class is used by all MessageDefinition subclasses to register
    and store the message definition data for subsequent retrieval and use.
    """
    RegisteredMessageDefinitions = {}
    MOST_RECENT = object()
    
    class DefinitionStoragePOD(object):
        def __init__(self):
            self.versions = {}
            self.majorMax = 0
            self.minorMax = {0:0}
    
    def __new__(cls, name, parents, dict):
        if "PLAYGROUND_IDENTIFIER" not in dict:
            raise InvalidProtocolDefinition("PLAYGROUND_IDENTIFIER required for a protocol definition")
        if "MESSAGE_VERSION" not in dict:
            raise InvalidProtocolDefinition("MESSAGE_VERSION required for a protocol definition")
        
        versionInfo = dict["MESSAGE_VERSION"].split(".")
        if len(versionInfo) != 2:
            raise InvalidProtocolDefinition("MESSAGE_VERSION must be exactly formulated as [x.y]")
        try:
            major = int(versionInfo[0])
        except:
            raise InvalidProtocolDefinition("MESSAGE_VERSION major number must be an integer")
        try:
            minor = int(versionInfo[1])
        except:
            raise InvalidProtocolDefinition("MESSAGE_VERSION minor number must be an integer")
        
        ident = dict["PLAYGROUND_IDENTIFIER"]
        
        pod = resolveDottedKey(ident, cls.RegisteredMessageDefinitions)
        if not pod:
            pod = cls.DefinitionStoragePOD()
            storeDottedKey(ident, cls.RegisteredMessageDefinitions, pod)
        if pod.versions.has_key((major,minor)):
            raise InvalidProtocolDefinition("Duplicate identifier " + ident + " for version " + dict["MESSAGE_VERSION"])
        
        dict["BODY"].append( ("playground_msgID", UINT8, DEFAULT_RANDOM8) )
        
        definitionCls = super(MessageDefinitionMetaClass, cls).__new__(cls, name, parents, dict)
        pod.versions[(major, minor)] = definitionCls
        
        if major > pod.majorMax: pod.majorMax = major
        if not pod.minorMax.has_key(major):
            pod.minorMax[major] = 0
        if minor > pod.minorMax[major]: pod.minorMax[major] = minor
        
        return definitionCls
    
    @classmethod
    def GetMessageDefinition(cls, identifier, version=MOST_RECENT, allowNewerMinorVersion=False):
        pod = resolveDottedKey(identifier, cls.RegisteredMessageDefinitions)
        if not pod: return None

        if version == cls.MOST_RECENT:
            return pod.versions[(pod.majorMax, pod.minorMax[pod.majorMax])]
        else:
            major, minor = version
            if not pod.versions.has_key(version) and pod.minorMax.has_key(major):
                if minor <= pod.minorMax[major]:
                    return pod.versions[ (major, pod.minorMax[major]) ]
            return pod.versions.get(version, None)
    
class StructuredData(ProtoFieldValue):
    """
    A StructuredData is a ProtoFieldValue, but it also represents a composite
    message with multiple fields. As a ProtoFieldValue, however, it means that
    a structure can be recursive.
    
    A StructuredData is parameterized on some kind of message definition class.
    The static method GetMessageBuilder is used to get a top-level Structured Data
    from the registered definitions stored in MessageDefinitionMetaClass. The
    StructuredData uses the definition to define all of its fields, potentially
    recursively.
    
    Fields are accessed using __getitem__ (e.g., StructuredData["fieldname"]).
    
    It supports serialization and deserialization. A packet only need add the
    playground packet header.
    
    It supports data(), which will return a simple struct with fields filled in.
    """
    
    IDVersionTemplate = "!B%dsB%ds" # Length followed by length-string
                                    # For message identifier and version
    
    class POD:
        """
        Simple structure for data holding. the "data" operation of 
        StructuredData returns a POD with the appropriate fields set.
        """
        pass
    
    @staticmethod
    def GetMessageBuilder(key, version=MessageDefinitionMetaClass.MOST_RECENT):
        """
        Given a dotted key, get the appropriate StructuredData parameterized
        with the correct builder definition. As this is a "top level" message
        builder, it will be initialized.
        
        If the specified version is not available, a search will be made
        for a newer minor version.
        """
        
        if type(key) == MessageDefinitionMetaClass and version==MessageDefinitionMetaClass.MOST_RECENT:
            builder = StructuredData(key)
        else:
            if type(key) == MessageDefinitionMetaClass:
                key = key.PLAYGROUND_IDENTIFIER
            builderDef = MessageDefinitionMetaClass.GetMessageDefinition(key, version)
            if not builderDef and version != MessageDefinitionMetaClass.MOST_RECENT:
                builderDef = MessageDefinitionMetaClass.GetMessageDefinition(key, version, allowNewerMinorVersion=True) 
            if not builderDef: return None
            builder = StructuredData(builderDef)
        
        builder.init()
        return builder
    
    @staticmethod
    def DeserializeStream(bufs):
        try:
            msgHandler = None
            nameLen, offset = getStreamUnpack(0, bufs, "!B")
            while nameLen == None:
                yield None
                nameLen, offset = getStreamUnpack(offset, bufs, "!B")
                
            name, offset = getStreamUnpack(offset, bufs, "!%ds" % nameLen)
            while name == None:
                yield None
                name, offset = getStreamUnpack(offset, bufs, "!%ds" % nameLen)
                
            versionLen, offset = getStreamUnpack(offset, bufs, "!B")
            while versionLen == None:
                yield None
                versionLen, offset = getStreamUnpack(offset, bufs, "!B")
                
            version, offset = getStreamUnpack(offset, bufs, "!%ds" % versionLen)
            while version == None:
                yield None
                version, offset = getStreamUnpack(offset, bufs, "!%ds" % versionLen)
                
            versionMajorStr, versionMinorStr = version.split(".")
            versionTuple = (int(versionMajorStr), int(versionMinorStr))
            
            msgHandler = StructuredData.GetMessageBuilder(name, versionTuple)
            if not msgHandler: 
                yield None
            else:
                trimStream(bufs, offset)
                streamIterator = msgHandler.deserializeStream(bufs)
                while streamIterator.next() == None:
                    yield None
                yield msgHandler
        except Exception, e:
            msg = "Deserialization failed: %s\n" % e
            msg += traceback.format_exc()
            raise DeserializationError(e, msg, msgHandler)
    
    @staticmethod
    def Deserialize(buf):
        offset = 0
        nameLen = struct.unpack_from("!B", buf, offset)[0]
        offset += struct.calcsize("!B")
        name = struct.unpack_from("!%ds" % nameLen, buf, offset)[0]
        offset += struct.calcsize("!%ds" % nameLen)
        versionLen = struct.unpack_from("!B", buf, offset)[0]
        offset += struct.calcsize("!B")
        version = struct.unpack_from("!%ds" % versionLen, buf, offset)[0]
        offset += struct.calcsize("!%ds" % versionLen)
        
        versionMajorStr, versionMinorStr = version.split(".")
        versionTuple = (int(versionMajorStr), int(versionMinorStr))
        
        msgHandler = StructuredData.GetMessageBuilder(name, versionTuple)
        if not msgHandler: 
            return (None, 0)
        actualBytes = msgHandler.deserialize(buf, offset)+offset
        return (msgHandler, actualBytes)
    
    def __init__(self, defClass):
        ProtoFieldValue.__init__(self)
        self.__defClass = defClass
        self.__fields = {}
        self.__tagMapping = {}
        self.__usedTags = {}
        self.__nextTag = 1
        self.__fieldOrder = []
        
    def __assignTag(self, fieldName, explicitTag = None):
        if not explicitTag:
            tag = self.__nextTag
            while self.__usedTags.has_key(tag):
                tag += 1
            self.__nextTag = tag+1
        else:
            if self.__usedTags.has_key(explicitTag):
                raise self.DuplicateTag(fieldName, self.__usedTags[explicitTag], explicitTag)
            tag = explicitTag
        self.__tagMapping[fieldName] = tag
        self.__usedTags[tag] = fieldName
        return tag
    
    def definitionClass(self):
        return self.__defClass

    def init(self):
        if self._data != self.UNSET:
            """ Already initialized. """
            return
        
        # self._data = self? Is this right?
        self._data = self.POD()
        for definition in self.__defClass.BODY:
            fieldName, fieldType, attributes = definition[0], definition[1], definition[2:]
            
            """ Ensure that fieldName is not duplicated """
            if fieldName in self.__fields:
                raise InvalidProtocolDefinition("Duplicated fieldname %s in handler %s" % (fieldName, self.__defClass.PLAYGROUND_IDENTIFIER))
            
            fieldData = fieldType()
            if not isinstance(fieldData, ProtoFieldValue):
                fieldData = StructuredData(fieldType)
                
            for attr in attributes:
                fieldData.registerAttribute(attr)
                if isinstance(attr, Initializer):
                    attr.initialize(fieldData)
                
            if not fieldData.hasAttribute(OPTIONAL):
                fieldData.registerAttribute(REQUIRED)
                
            self.__fields[fieldName] = fieldData
            self.__assignTag(fieldName)
            self.__fieldOrder.append(fieldName)
            
    def isMessageDefinition(self):
        return issubclass(self.__defClass, MessageDefinition)
            
    def topLevelData(self):
        if self.isMessageDefinition():
            return (self.__defClass.PLAYGROUND_IDENTIFIER, self.__defClass.MESSAGE_VERSION)
        return (None, None)
            
    def data(self):
        if self._data != self.UNSET:
            for fieldName in self.__fields.keys():
                fieldData = self.__fields[fieldName].data()
                if fieldData != self.UNSET:
                    setattr(self._data, fieldName, self.__fields[fieldName].data())
        return self._data
            
    def __getitem__(self, key):
        return self.__fields[key]
        
    def validate(self):
        structureValidate = ProtoFieldValue.validate(self)
        if not structureValidate: return structureValidate
        
        for field in self.__fields.keys():
            fieldValidate = self.__fields[field].validate()
            if not fieldValidate:
                return FieldError(field, fieldValidate)
        return Validated()
    
    def serialize(self):
        if self.isMessageDefinition():
            messageValid = self.validate()
            if not messageValid:
                raise messageValid
        buf = ""
        fieldCount = 0
        for fieldName in self.__fieldOrder:
            if self.__fields[fieldName].data() == ProtoFieldValue.UNSET:
                continue
            fieldCount += 1
            buf += struct.pack('!H',self.__tagMapping[fieldName])
            buf += self.__fields[fieldName].serialize()
        buf = struct.pack("!H",fieldCount) + buf
        if issubclass(self.__defClass, MessageDefinition):
            msgID, version = (self.__defClass.PLAYGROUND_IDENTIFIER, self.__defClass.MESSAGE_VERSION)
            packCode = StructuredData.IDVersionTemplate % (len(msgID), len(version))
            msgHeader = struct.pack(packCode, len(msgID), msgID, 
                                    len(version), version)
            buf = msgHeader + buf
        return buf
    
            
    def deserializeStream(self, bufs):
        """
        Deserialize stream. Deserializes based on
        an array of buffers that is presumed to be
        refilled from outside the iterator. Iterates
        None until it is fully restored, then 
        yields itself. Will return unused bytes
        to the buffers as a single buffer.
        """
        self.init()
        # this offset is local to a given buffer in the stream
        # an optimization only so there's less string splitting
        offset = 0
        (fieldCount, offset) = getStreamUnpack(offset, bufs, "!H")
        while fieldCount == None: 
            yield None
            (fieldCount, offset) = getStreamUnpack(offset, bufs, "!H")
        
        for i in range(fieldCount):
            (fieldID, offset) = getStreamUnpack(offset, bufs, "!H")
            while fieldID == None: 
                yield None
                (fieldID, offset) = getStreamUnpack(offset, bufs, "!H")
            offset = trimStream(bufs, offset)
            fieldName = self.__usedTags[fieldID]
            # get rid of the buffer up to the offset. We don't pass offset
            streamIterator = self.__fields[fieldName].deserializeStream(bufs)
            while streamIterator.next() == None:
                yield None
        yield self
    
    def deserialize(self, buf, offset=0):
        self.init()
        structOffset = 0
        fieldCount = struct.unpack_from("!H", buf, offset + structOffset)[0]
        structOffset += struct.calcsize("!H")
        for i in range(fieldCount):
            fieldID = struct.unpack_from("!H", buf, offset + structOffset)[0]
            structOffset += struct.calcsize("!H")
            fieldName = self.__usedTags[fieldID]
            structOffset += self.__fields[fieldName].deserialize(buf, offset + structOffset)
        return structOffset
    
    def __str__(self):
        identifier = "ptr :%d" % id(self)
        if self.__fields.has_key("playground_msgID"):
            identifier = "msgId :%s" % str(self.__fields["playground_msgID"].data())
        return "<%s(%s) %s" % (self.__defClass.PLAYGROUND_IDENTIFIER, self.__defClass.MESSAGE_VERSION, identifier)
    
    def __repr__(self):
        return str(self)
    
class MessageDefinition(object):
    """
    This class should be the base class of all Message Definition
    classes that define some serializable network message.
    
    Every Message Definition needs to define its own PLAYGROUND_IDENTIFIER
    and MESSAGE_VERSION field. Any fields must be defined in a class variable
    called BODY. BODY is a list of fields, where every field has the following
    definition:
      (NAME, TYPE, *ATTRIBUTES)
    """
    __metaclass__ = MessageDefinitionMetaClass
    PLAYGROUND_IDENTIFIER = "base.definition"
    MESSAGE_VERSION = "0.0"
    BODY = []

"""
This needs moved to a utility class/module
def bufferToByteString(buf):
    s = ""
    bytecount = 0
    for byte in buf:
        bytecount += 1
        hb = hex(ord(byte))[2:]
        if len(hb) == 1: hb = '0'+hb
        s += hb
        if bytecount % 8 == 7: s += " "
    return s
"""
    
"""
This needs to be moved to a test class
if __name__ == "__main__":
    class TestDef(MessageDefinition):
        class SubDef:
            BODY = [
                    ("subfield1", STRING),
                    ("subfield2", UINT4, Bounded(min=5,max=5))
                    ]
            
        PLAYGROUND_IDENTIFIER="playground.snielson.test.message1"
        MESSAGE_VERSION = "1.0"
        BODY = [
                ("field1", UINT4, Bounded(min=1,max=10), OPTIONAL),
                ("list1", LIST(UINT4), FixedSize(3)),
                ("recursivefield1", SubDef, OPTIONAL)
                ]
        
    p = ProtoBuilder()
    builder = p.getBuilder("playground.snielson.test.message1")
    builder["field1"].setData(3)
    builder["list1"].add(3)
    builder["list1"][0].setData(1)
    builder["list1"][1].setData(2)
    builder["list1"][2].setData(3)
    builder["recursivefield1"].init()
    builder["recursivefield1"]["subfield1"].setData("hello")
    builder["recursivefield1"]["subfield2"].setData(0)
    print builder
    print builder["field1"]
    print builder["list1"]
    print builder["field1"].data()
    print builder["list1"].data()
    print builder["list1"][0].data()
    print builder["recursivefield1"]["subfield1"].data()
    print builder["recursivefield1"]["subfield2"].data()
    print builder.validate()
    msg = builder.serialize()
    print bufferToByteString(msg)
    builder2 = p.getBuilder("playground.snielson.test.message1")
    builder2.deserialize(msg)
    print "deserialized"
    print builder2["field1"].data()
"""