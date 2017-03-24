from bot.common.network import ReprogrammingRequest
import md5

from joblib import Parallel, delayed
import multiprocessing


def crackRequestPW(msg):
    realChecksum = msg.Checksum

    for i in range(999999):
        pw = checkPw(msg,i, realChecksum)
        if pw:
            return pw

def checkPw(msg, pwnum, realCS):
    pw = "0"*(6-len(str(pwnum))) + str(pwnum)
    msg.Checksum = pw
    testChecksum = md5.new(msg.__serialize__()).hexdigest()
    if testChecksum == realCS:
        return pw

def parCrack(msg):
    num_cores = multiprocessing.cpu_count()
    results = Parallel(n_jobs=num_cores)(delayed(checkPw)(msg,i,msg.Checksum) for i in range(999999))
    return results

if __name__ == "__main__":
    s = "+cyberward.botinterface.ReprogrammingRequest\x031.0\x00\x06\x00\x01\x00\x00\x00\x01\x00\x02\x00\x00\x00 59a42a27f07347f94d5d9fa58fa51ba3\x00\x03\x00\x00\x04\x00\x00\x00\x05\x00\x0b\x00\x00\x00\x01H\x00\x00\x00\x01E\x00\x00\x00\x01L\x00\x00\x00\x01L\x00\x00\x00\x01O\x00\x00\x00\x01 \x00\x00\x00\x01W\x00\x00\x00\x01O\x00\x00\x00\x01R\x00\x00\x00\x01L\x00\x00\x00\x01D\x00\x06\xff]o\xb7\xd3\xd8\x8f\xf4"

    req, bytesUsed = ReprogrammingRequest.Deserialize(s)

    print(parCrack(req))


