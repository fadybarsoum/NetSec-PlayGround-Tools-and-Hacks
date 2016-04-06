'''
Created on Aug 20, 2013

@author: sethjn
'''
import struct

from playground.error import ErrorHandlingMixin

import logging, zlib, random
logger = logging.getLogger(__name__)

## TODO: change static methods to class methods

class Packet(ErrorHandlingMixin):
    '''
    The Packet class is not instantiated and serves primarily as a namespace.
    It groups together the operations necessary to create "raw wire"
    packets for bare (virtual) metal transport
    
    Analogous to Ethernet, Packets are "framed". A magic number 
    starts the sequence, but a random (or fixed) number is used
    for marking packet chunks. If the seed doesn't trail each
    chunk, something's gone wrong and it can try to correct.
    
    There is no final terminal as the Checksum is sufficient
    at that point. Checksum is calculated
    over the entire packet excluding the header
    '''
    
    # PLAYGROUND's magic prefix 05 08 0D 15
    #   Followed by the length of the packet (minus header)
    #   Followed by a Framing size (2 bytes, max frame is 65k)
    #   Followed by a Frame terminal (4 bytes)
    #   Followed by a packet checksum (4 bytes)
    MAGIC_PREFIX = 0x05080D15
    HEADER_PREFIX_FORMAT = "!IIHII"
    HEADER_PREFIX_SIZE = struct.calcsize(HEADER_PREFIX_FORMAT)
    
    TRAILER_FORMAT = "!I"
    TRAILER_SIZE = struct.calcsize(TRAILER_FORMAT)
    
    BUFFER_STATUS_NO_HEADER_YET = "Not enough length for packet playground header yet"
    BUFFER_STATUS_INCOMPLETE = "Buffer not yet complete for full packet"
    BUFFER_STATUS_NO_MAGIC_PREFIX = "Buffer does not start with magic prefix"
    BUFFER_STATUS_CONTAINS_MESSAGE = "Buffer contains at least one packet"
    BUFFER_STATUS_BAD_CHECKSUM = "Bad Checksum"
    BUFFER_STATUS_BAD_FRAMING = "Trailer not found for frame"
    
    BUFFER_STATUS_ERRORS = [
                            BUFFER_STATUS_NO_MAGIC_PREFIX,
                            BUFFER_STATUS_BAD_CHECKSUM,
                            BUFFER_STATUS_BAD_FRAMING,
                            ]
    
    @staticmethod
    def GetChecksum(buf):
        return zlib.adler32(buf)%(2**32)
    
    @staticmethod
    def CreatePacketFrames(buf, framingSize=(2**14), seed=0):
        """
        Given an initialized message definition, generate the serialized packet. The
        packet will include a PLAYGROUND header:
        
        [ MAGIC NUMBER (4 bytes) | MESSAGE LEN (4 bytes) |
          FRAMING SIZE (2 bytes) | TERMINAL (4 bytes) 
          CRC32 (4 bytes) 
          ]
        
        Note that the Message Length ignores the header.
        """
        if framingSize < (2**8):
            raise Exception("Framing size cannot be smaller than 256")
        if seed == 0: seed = random.randint(0,(2**32)-1)
        
        # CRC is over the original data
        crc32 = Packet.GetChecksum(buf)
        data = buf
        
        # len includes frames (added a few lines down)
        msgBufLen = len(buf)
        frames = []
        while data:
            frames.append(data[:framingSize])
            data = data[framingSize:]
            # for all packets but the last one, append the seed for framing
            if data:
                packedSeed = struct.pack(Packet.TRAILER_FORMAT,seed)
                msgBufLen += Packet.TRAILER_SIZE
                frames[-1] = frames[-1] + packedSeed
                #buf += frames[-1]
        
        # We are being very suboptimal here. We break the packet apart
        # then put it back together multiple times. Come up with
        # better solution
        
        header = struct.pack(Packet.HEADER_PREFIX_FORMAT, 
                             Packet.MAGIC_PREFIX, msgBufLen,
                             framingSize, seed, crc32)
        
        frames[0] = header + frames[0]
        
        return frames
    
    @staticmethod
    def MsgToPacketFrames(msg, framingSize=(2**14)):
        rawBuffer = msg.serialize()
        frames = Packet.CreatePacketFrames(rawBuffer, framingSize)
        return frames
    
    @staticmethod
    def MsgToPacketBytes(msg, framingSize=(2**14)):
        packetBytes = ""
        frames = Packet.MsgToPacketFrames(msg, framingSize)
        for frame in frames:
            packetBytes += frame
        return packetBytes
    
    @staticmethod
    def RestorePacket(buf, offset=0):
        """
        Given a buffer, determine if an entire message has been received. It first checks
        if a header has been received. If so, it unpacks the length from the header and
        then sees if the buffer is appropriately large.
        """
        bufLen = len(buf) - offset
        if bufLen < Packet.HEADER_PREFIX_SIZE: 
            return (Packet.BUFFER_STATUS_NO_HEADER_YET, "Missing %d bytes for header" % (Packet.HEADER_PREFIX_SIZE - bufLen))
        prefix, packetLen, framingSize, seed, crc32 = struct.unpack_from(Packet.HEADER_PREFIX_FORMAT, buf, offset)
        if prefix != Packet.MAGIC_PREFIX:
            return (Packet.BUFFER_STATUS_NO_MAGIC_PREFIX, "Prefix is %d" % prefix)
        
        # rebuildOffset. The start of the packet data
        rebuildOffset = Packet.HEADER_PREFIX_SIZE + offset
        
        # maxPacketOffset. The end of the packet data (start + packetLen, which includes frames)
        maxPacketOffset = rebuildOffset + packetLen
        
        # the frames restored
        frames = [] 
        
        # while our local offset plus another frame is less than the length of the packet
        # also check the length of the buffer. We have to do both. If we check the packet size,
        # we might be working with a "too small" buffer. But if we check the buffer,
        # we can go past the length of the packet
        while (rebuildOffset+framingSize) < maxPacketOffset and (rebuildOffset+framingSize) < len(buf):
            
            # seedOffset is the location of the seed demarcating the end of the frame
            # It's the start of the packet + the current frame start + frame size
            seedOffset = rebuildOffset + framingSize
            
            if Packet.TRAILER_SIZE > (len(buf)-seedOffset):
                return (Packet.BUFFER_STATUS_BAD_FRAMING, "Inconsistent internal length")
            # we've restored the seed from the end of the frame
            trailerSeed = struct.unpack_from(Packet.TRAILER_FORMAT, buf, seedOffset)[0]
            if trailerSeed != seed:
                return (Packet.BUFFER_STATUS_BAD_FRAMING, "Expected trailer missing")
            
            # Within the buffer, the frame starts here
            frames.append(buf[rebuildOffset:seedOffset])
            rebuildOffset += framingSize + Packet.TRAILER_SIZE
        # get the last frame. It goes from the current frame offset to the end of the packet
        frames.append(buf[rebuildOffset:maxPacketOffset])
        if bufLen >= (packetLen + Packet.HEADER_PREFIX_SIZE):
            fullPacket = "".join(frames)
            computedChecksum = Packet.GetChecksum(fullPacket)
            if computedChecksum != crc32:
                return (Packet.BUFFER_STATUS_BAD_CHECKSUM, "Checksum didn't match")
            return (Packet.BUFFER_STATUS_CONTAINS_MESSAGE, (fullPacket, maxPacketOffset))
        return (Packet.BUFFER_STATUS_INCOMPLETE, "Missing %d bytes for body" % ((packetLen + Packet.HEADER_PREFIX_SIZE) - bufLen))

class PacketStorage(object):
    """
    This class holds an incoming buffer until a full packet
    arrives.
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
        
    def popPacket(self, errorReporter=None):
        """
        Returns none until a full packet is received
        """
        prefixOffset = 0
        resultCode, args = Packet.RestorePacket(self.storage, prefixOffset)
        while resultCode in Packet.BUFFER_STATUS_ERRORS:
            prefixOffset += 1
            resultCode, args = Packet.RestorePacket(self.storage, prefixOffset)        
        if prefixOffset:
            logger.info("%d bytes of data corrupted or otherwise skipped." % prefixOffset)
        
        if resultCode in [Packet.BUFFER_STATUS_INCOMPLETE,
                          Packet.BUFFER_STATUS_NO_HEADER_YET]:
            logger.debug("Packet not ready. Cutting off %d bad bytes" % prefixOffset)
            self.storage = self.storage[prefixOffset:]
            return None
        
        if resultCode == Packet.BUFFER_STATUS_CONTAINS_MESSAGE:
            packet, newOffset = args
            self.storage = self.storage[newOffset:]
            return packet
        
        else:
            logger.debug("Unknown result code %s" % resultCode)
            #errorReporter.reportError("Unknown packet unpack result code %s" % resultCode)
        return None