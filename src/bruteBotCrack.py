from bot.common.network import ReprogrammingRequest
import md5

def crackRequestPW(msg):
   realChecksum = req.Checksum

    for i in range(999999):
        pw = "0"*(6-len(str(i))) + str(i)
        req.Checksum = pw
        testChecksum = md5.new(req.__serialize__()).hexdigest()
        if testChecksum == realChecksum:
            return rw


if __name__ == "__main__":
    s = "+cyberward.botinterface.ReprogrammingRequest\x031.0\x00\x06\x00\x01\x00\x00\x00\x01\x00\x02\x00\x00\x00 59a42a27f07347f94d5d9fa58fa51ba3\x00\x03\x00\x00\x04\x00\x00\x00\x05\x00\x0b\x00\x00\x00\x01H\x00\x00\x00\x01E\x00\x00\x00\x01L\x00\x00\x00\x01L\x00\x00\x00\x01O\x00\x00\x00\x01 \x00\x00\x00\x01W\x00\x00\x00\x01O\x00\x00\x00\x01R\x00\x00\x00\x01L\x00\x00\x00\x01D\x00\x06\xff]o\xb7\xd3\xd8\x8f\xf4"

    req, bytesUsed = ReprogrammingRequest.Deserialize(s)

    print(crackRequestPW(s))


