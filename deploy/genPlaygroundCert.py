
import sys, os, random

def getPlaygroundVars(template):
    pvars = {}
    for line in template.split("\n"):
        line = line.strip()
        if not line: continue
        if not line[0] == "#": continue
        while line and line[0] == "#":
            line = line[1:] # get rid of initial hash mark
        line = line.strip()
        if not line: continue
        if line.find("[PG]") != 0: continue
        line = line[4:] # strip off "[PG]"
        if line.find("#") > 0:
            line = line[:line.find("#")] # get line to next comment
        line = line.strip()
        if not line: continue
        parts = line.split("=")
        if len(parts) != 2:
            raise Exception("Expected '# [PG] k=v'")
        k,v = parts
        pvars[k.strip().upper()] = v.strip()
    return pvars

def genCert(basename, instructionTemplate, CA=None, CAkey=None, tmpFileTemplate="gencert.cnf"):
    commonname = basename
    basename = basename.replace(" ","_")
    cnfFileName = basename+"."+tmpFileTemplate
    ret = 0
    with open(cnfFileName, "w+") as f:
        f.write(instructionTemplate)
        f.write("\ncommonName_default = " + commonname + "\n")
    try:
        genKeyStr = 'openssl genrsa -out %s.key 2048' % basename
        genCsrStr = 'openssl req -new -key %s.key -out %s.csr -config %s -batch' % (basename, basename, cnfFileName)
        if CA:
            signCertStr = 'openssl x509 -req -days 360 -in %s.csr -CA %s -CAkey %s -out %s_signed.cert -set_serial %d' % (basename, CA, CAkey, basename, random.randint(1,100000))
        else:
            signCertStr = 'openssl x509 -req -days 360 -in %s.csr -signkey %s.key -out  %s_signed.cert -set_serial %d' % (basename, basename, basename, random.randint(1,100000))
        
        os.system(genKeyStr)
        os.system(genCsrStr)
        os.system(signCertStr)
        os.unlink("%s.csr"%basename)
    except Exception, e:
        print "Could not complete operation", e
        ret = -1
    os.unlink(cnfFileName)
    return ret

def signCSR(csrfile, CA, CAkey, interactive=True):
    basename = csrfile.replace(".csr","")
    certname = "%s_signed.cert" % basename
    serial = random.randint(1,100000)
    if interactive:
        showDataStr = 'openssl req -in %s -subject' % csrfile
        os.system(showDataStr)
        result = raw_input("Certificate OK? ")
        if result[0].lower() != "y":
            return "aborted"
    signCertStr = 'openssl x509 -req -days 360 -in %s' % csrfile
    signCertStr += ' -CA %s' % CA
    signCertStr += ' -CAkey %s' % CAkey 
    signCertStr += ' -out %s' % certname
    signCertStr += ' -set_serial %d' % serial
    os.system(signCertStr)
    if interactive:
        showDataStr = 'openssl x509 -in %s -subject -serial' % certname
        os.system(showDataStr)
        raw_input("Generated signed cert with above referenced serial number. Press enter to quit. ")
    return 0

def usage():
    print "USAGE: %s <cnf file> [<addr3>] [<addr4>]" % sys.argv[0]
    print "USAGE: %s raw <cnf file> <raw_name>" % sys.argv[0]
    print "USAGE: %s sign <sign_cert> <sign_key> [csrs...]" % sys.argv[0]
    print "  addr3 and addr4 can only be used if cnf file specifies"
    print "  a group code."

if __name__ == "__main__":
    if "--help" in sys.argv or len(sys.argv) < 2:
        usage()
        sys.exit(-1)
    template = ""
    if sys.argv[1] == "raw":
        if len(sys.argv) != 4:
            usage()
            sys.exit(-1)
        templateFile = sys.argv[2]
        rawName = sys.argv[3]
        with open(templateFile) as f:
            template = f.read()
        ret = genCert(rawName, template)
    elif sys.argv[1] == "sign":
        for csr in sys.argv[4:]:
            signCSR(csr, sys.argv[2], sys.argv[3])
        ret = 0
    else:
        templateFile = sys.argv[1]
        with open(templateFile) as f:
            template = f.read()
        playgroundVars = getPlaygroundVars(template)
        
        playgroundAddrBase = int(playgroundVars["BASE"])
        teamCode = playgroundVars.get("TEAMCODE",'')
        if teamCode != '': 
            teamCode = int(teamCode)
        
        addr3, addr4 = None, None
        if len(sys.argv) > 2:
            if teamCode == '':
                usage()
                sys.exit(-1)
            addr3 = int(sys.argv[2])
            if len(sys.argv) > 3:
                addr4 = int(sys.argv[3])
        
        playgroundAddr = "%s" % playgroundAddrBase
        if teamCode != '':
            playgroundAddr += ".%d" % teamCode
        if addr3 != None:
            playgroundAddr += ".%d" % addr3
        if addr4 != None:
            playgroundAddr += ".%d" % addr4
        CA = playgroundVars.get("CA",None)
        CAkey = playgroundVars.get("CAKEY",None)
        ret = genCert(playgroundAddr, template, CA, CAkey)
    sys.exit(ret)
