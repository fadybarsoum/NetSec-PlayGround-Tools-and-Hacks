'''
Created on Aug 20, 2013

@author: sethjn
'''
import struct

from playground.network.message import MessageData
from playground.error import ErrorHandlingMixin
from Error import PacketSerializationError, PacketReconstructionError

import logging, zlib
logger = logging.getLogger(__name__)

## TODO: change static methods to class methods

class Packet(ErrorHandlingMixin):
    '''
    The Packet class is not instantiated and serves primarily as a namespace.
    It groups together the operations necessary to serialize and deserialize
    Playground messages.
    '''
    
    MAGIC_PREFIX = 0x91A7584D
    HEADER_PREFIX_FORMAT = "!QQI"
    HEADER_PREFIX_SIZE = struct.calcsize(HEADER_PREFIX_FORMAT)
    
    BUFFER_STATUS_NO_HEADER_YET = "Not enough length for packet playground header yet"
    BUFFER_STATUS_INCOMPLETE = "Buffer not yet complete for full message"
    BUFFER_STATUS_NO_MAGIC_PREFIX = "Buffer does not start with magic prefix"
    BUFFER_STATUS_CONTAINS_MESSAGE = "Buffer contains at least one message"
    BUFFER_STATUS_BAD_LEN = "Buffer length checksum mismatch"
    
    @staticmethod
    def lengthChecksum(mLen):
        """
        Not happy about adding on a full 4 bytes...
        """
        return zlib.adler32(struct.pack("!Q",mLen))
    
    @staticmethod
    def SerializeMessage(msgDef):
        """
        Given an initialized message definition, generate the serialized packet. The
        packet will include a PLAYGROUND header:
        
        [ MAGIC NUMBER (8 bytes) | Message Length (8 bytes) | Length Checksum (2 bytes) ]
        
        Note that the Message Length ignores the header.
        """
        msgID, version = msgDef.topLevelData()
        if not msgID or not version:
            raise PacketSerializationError("Cannot serialize message definition, it is missing a PLAYGROUND_IDENTIFIER and/or VERSION")
        validationResult = msgDef.validate()
        if isinstance(validationResult, Exception):
            raise validationResult
        msgBuf = msgDef.serialize()
        msgBuf = struct.pack("!B%dsB%ds" % (len(msgID), len(version)), len(msgID), msgID, len(version), version) + msgBuf
        msgBufLen = len(msgBuf)
        header = struct.pack(Packet.HEADER_PREFIX_FORMAT, Packet.MAGIC_PREFIX, msgBufLen, Packet.lengthChecksum(msgBufLen))
        return header + msgBuf
    
    @staticmethod
    def BufferStatus(buf, offset=0):
        """
        Given a buffer, determine if an entire message has been received. It first checks
        if a header has been received. If so, it unpacks the length from the header and
        then sees if the buffer is appropriately large.
        """
        bufLen = len(buf) - offset
        if bufLen < Packet.HEADER_PREFIX_SIZE: 
            return (Packet.BUFFER_STATUS_NO_HEADER_YET, "Missing %d bytes for header" % (Packet.HEADER_PREFIX_SIZE - bufLen))
        prefix, fullLen, chk = struct.unpack_from(Packet.HEADER_PREFIX_FORMAT, buf, offset)
        if prefix != Packet.MAGIC_PREFIX:
            return (Packet.BUFFER_STATUS_NO_MAGIC_PREFIX, "Prefix is %d" % prefix)
        if chk != Packet.lengthChecksum(fullLen):
            return (Packet.BUFFER_STATUS_BAD_LEN, "Bad length checksum. Expected %d but got %d" % (chk, Packet.lengthChecksum(fullLen)))
        if bufLen >= (fullLen + Packet.HEADER_PREFIX_SIZE):
            return (Packet.BUFFER_STATUS_CONTAINS_MESSAGE, None)
        return (Packet.BUFFER_STATUS_INCOMPLETE, "Missing %d bytes for body" % ((fullLen + Packet.HEADER_PREFIX_SIZE) - bufLen))
    
    @staticmethod
    def DeserializeMessage(buf, offset=0):
        """
        Deserializes a PLAYGROUND packet. This method assumes that the buffer is complete
        so client code should check with HasFullMessage first.
        
        At present, Deserialize does nothing to check the version although this will change
        in the future.
        
        2/15/2014 - Added version management
        """
        prefix, fullLen, chk = struct.unpack_from(Packet.HEADER_PREFIX_FORMAT, buf, offset)
        if prefix != Packet.MAGIC_PREFIX:
            raise PacketReconstructionError("Buffer does not point to the beginning of a playground message!")
        if chk!= Packet.lengthChecksum(fullLen):
            raise PacketReconstructionError("Buffer length has invalid checksum")
        offset += Packet.HEADER_PREFIX_SIZE
        
        nameLen = struct.unpack_from("!B", buf, offset)[0]
        offset += struct.calcsize("!B")
        name = struct.unpack_from("!%ds" % nameLen, buf, offset)[0]
        offset += struct.calcsize("!%ds" % nameLen)
        
        versionLen = struct.unpack_from("!B", buf, offset)[0]
        offset += struct.calcsize("!B")
        version = struct.unpack_from("!%ds" % versionLen, buf, offset)[0]
        offset += struct.calcsize("!%ds" % versionLen)
        
        idLen = struct.calcsize("!B%dsB%ds" % (nameLen, versionLen))
        
        versionMajorStr, versionMinorStr = version.split(".")
        versionTuple = (int(versionMajorStr), int(versionMinorStr))
        
        msgHandler = MessageData.GetMessageBuilder(name, versionTuple)
        if msgHandler == None:
            raise PacketReconstructionError("Could not deserialize type %s (%s)" % (name, version))
        actualBytes = msgHandler.deserialize(buf, offset)
        if actualBytes != (fullLen - idLen):
            raise Exception("Invalid packet. Expected size and actual size mismatch.")
        return (msgHandler, fullLen + Packet.HEADER_PREFIX_SIZE)

class PacketStorage(object):
    """
    This class holds an incoming buffer until a full message
    can be deserialized from it.
    """
    def __init__(self):
        self.storage = ""
        
    def update(self, buf):
        """
        This method combines the incoming buffer with previously
        received data.
        """
        
        # This mechanism is very slow. TODO: something faster
        self.storage += buf
        
    def popMessage(self, errorReporter=None):
        """
        If a packet can be deserialized, the newly constructed
        message is returned and the appropriate data removed from storage.
        Client code should repeatedly call popMessage until it returns None.
        """
        prefixOffset = 0
        while prefixOffset < len(self.storage) and Packet.BufferStatus(self.storage, prefixOffset)[0] in [Packet.BUFFER_STATUS_NO_MAGIC_PREFIX, Packet.BUFFER_STATUS_BAD_LEN]:
            prefixOffset += 1
        self.storage = self.storage[prefixOffset:]
        try:
            if Packet.BufferStatus(self.storage)[0] == Packet.BUFFER_STATUS_CONTAINS_MESSAGE:
                handler, packetSize = Packet.DeserializeMessage(self.storage)
                self.storage = self.storage[packetSize:]
                logger.debug("Packet::popMessage() Got handler for fully recovered message")
                return handler
            else:
                logger.debug("Packet::popMessage() status is %s (storage size %d)" % (Packet.BufferStatus(self.storage), len(self.storage)))
        #except PacketReconstructionError, e:
        except Exception, e:
            """
            I am uncomfortable trapping all exceptions in this way. I would
            prefer to only catch PacketReconstructionErrors here. However, it is
            critical that the layer not die because of a bit error. Accordingly, 
            all error messages are now trapped.
            """
            if errorReporter:
                errorReporter.reportException(e)
            
            """
            Try to find the beginning of an uncorrupted stream
            """
            prefixOffset = 1
            while prefixOffset < len(self.storage) and not Packet.BufferStatus(self.storage, prefixOffset)[0] in [Packet.BUFFER_STATUS_NO_MAGIC_PREFIX, Packet.BUFFER_STATUS_BAD_LEN]:
                prefixOffset + 1
            self.storage = self.storage[prefixOffset:]
            return self.popMessage(errorReporter)
        return None