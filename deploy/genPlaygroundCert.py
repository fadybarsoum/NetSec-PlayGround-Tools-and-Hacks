
import sys, os, random, collections

class Cnf(object):
    def __init__(self):
        self.__asData = {}
    
    @classmethod
    def TxtLinesToData(cls, txtLines):
        section = None
        data = collections.OrderedDict()
        for line in txtLines:
            commentPos = line.find('#')
            if commentPos >= 0:
                line = line[:commentPos]
            line = line.strip()
            if not line: continue
            if line[0] == '[':
                section = line[1:-1].strip()
                data[section] = data.get(section,collections.OrderedDict())
            elif not section:
                print line, section
                raise Exception("Key outside of section")
            else:
                k,v = line.split("=")
                k,v = k.strip(), v.strip()
                data[section][k] = v
        return data
    
    @classmethod
    def DataToTxt(cls, data):
        cnfTxtLines = []
        for section in data.keys():
            cnfTxtLines.append("[ %s ]" % section)
            for key in data[section].keys():
                cnfTxtLines.append("%s = %s" % (key, data[section][key]))
            cnfTxtLines.append("")
        return cnfTxtLines
    
    def loadText(self, txt):
        self.__asData.update(self.TxtLinesToData(txt.split('\n')))
    
    def loadData(self, section, *keyVals):
        self.__asData[section] = self.__asData.get(section, collections.OrderedDict())
        for key, val in keyVals:
            self.__asData[section][key] = val
        
    def __getitem__(self, section):
        return self.__asData[section]
    
    def sections(self):
        return self.__asData.keys()
    
    def hasSection(self, section):
        return self.__asData.has_key(section)
    
    def toCnfLines(self):
        return self.DataToTxt(self.__asData)
    
def createCommonNameFromPlaygroundAddr(config):
    if config.hasSection("playground"):
        playgroundSection = config["playground"]
        blocks = map(lambda k: playgroundSection.get(k,None), ["BLOCK1", "BLOCK2",
                                                               "BLOCK3", "BLOCK4"])
        
        # the last blocks can be None... pop them off.
        while blocks and blocks[-1] == None: blocks.pop(-1)
        
        # But we can't have block 1 and block 3 specified... blocks have to be contig
        if None in blocks: return False
        
        # There must be at least one block
        if not blocks: return False
        name = ".".join(blocks)
        
        if len(blocks) != 4 and name[-1] != ".":
            name += "." # put a dot at the end of partial addresses
        config.loadData("req_distinguished_name", ("commonName_default", name))
        return True
    return False
    
def genKey(privateKeyFile, config, defaultKeySize = 1024):
    keySize = defaultKeySize
    if config.hasSection('req') and config['req'].has_key("default_bits"):
        keySize = int(config['req']['default_bits'])
    genKeyStr = 'openssl genrsa -out %s %d' % (privateKeyFile, keySize)
    if os.system(genKeyStr) != 0:
        raise Exception("Command '%s' failed." % genKeyStr)

def genCSR(privateKeyFile, config):
    if not config.hasSection("req_distinguished_name") or not config["req_distinguished_name"].has_key("commonName_default"):
        raise Exception("No common name defined")
    name = config["req_distinguished_name"]["commonName_default"].replace(' ','_')

    cnfFileName = name+".autogenerated.cnf"
    with open(cnfFileName,"w+") as f:
        f.write("\n".join(config.toCnfLines()))
        
    genCsrStr = 'openssl req -new -key %s -out %s.csr -config %s -batch' % (privateKeyFile, name, cnfFileName)
    result = os.system(genCsrStr)
    os.unlink(cnfFileName)
    if result != 0:
        raise Exception("Cmd '%s' failed." % genCsrStr)
    return "%s.csr" % name

def genCert(csrFile, config, privateKeyFile=None, CA=None, CAkey=None, eraseCsr=False):
    
    if not config.hasSection("req_distinguished_name") or not config["req_distinguished_name"].has_key("commonName_default"):
        raise Exception("No common name defined")
    name = config["req_distinguished_name"]["commonName_default"].replace(' ','_')

    cnfFileName = name+".autogenerated.cnf"
    with open(cnfFileName,"w+") as f:
        f.write("\n".join(config.toCnfLines()))
        
    if CA:
        signCertStr = 'openssl x509 -req -days 360 -in %s -CA %s -CAkey %s -out %s_signed.cert -set_serial %d' 
        signCertStr = signCertStr % (csrFile, CA, CAkey, name, random.randint(1,1000000))
    elif privateKeyFile:
        signCertStr = 'openssl x509 -req -days 360 -in %s -signkey %s -out  %s_signed.cert -set_serial %d' 
        signCertStr = signCertStr % (csrFile, privateKeyFile, name, random.randint(1,1000000))
    else:
        signCertStr = 'openssl x509 -req -days 360 -in %s -out %s_UNSIGNED.cert -set_serial %d'
        signCertStr = signCertStr % (csrFile, name, random.randint(1,1000000))
        
    result = os.system(signCertStr)
    if eraseCsr:
        os.unlink(csrFile)
    os.unlink(cnfFileName)
    if result != 0:
        raise Exception("Cmd '%s' failed" % signCertStr)
    return "%s_signed.cert" % name

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

def usage(exit=None):
    print """"
USAGE: %(PROG)s KEY <key file> [<cnf file>]
    Generates a key. If a cnf file is specified, it uses said file to determine how big the key is
    
USAGE: %(PROG)s CSR <cnf file> [--key=<key file>] [--name=<common name>] [--pgAddr=]
    Generates a CSR file.
    
    If --key is specified, said key will be used to generate the CSR. Otherwise, a NEW key will
    be auto generated.
    
    The CSR operation MUST be able to figure out a name for the CSR. The name is used 
    for the CSR's common name as well as the name of the csr file (and key file if it is
    also being generated).
    
    The CSR's name can be specified explicitly with --name.
    
    If --name is NOT specified, the script checks the cnf file. If the cnf file has
    a commonName_default key, that is used for the name of the CSR.
    
    If --name is not specified and commonName_default is not found in the cnf file, it
    will look for a [ playground ] section. An address is specified by each component
    block. In other words, if BLOCK1=x, BLOCK2=y the common name will be "x.y.".
    
    --pgAddr can be used to specify blocks not specified in the conf file. You may want,
    for example, to have the blocks 1-3 specified in the conf file, but specify the
    4th block at the command line (so that you do not have to make a new cnf file for
    every address). --pgAddr takes a single number, or a comma separated list of numbers.
    These numbers are the final blocks of the address so --pgAddr=100,50 specifies
    that BLOCK3 is 100 and BLOCK4 is 50. --pgAddr=0 specifies BLOCK4 = 0. --pgAddr
    will overwrite the block specifications of the config file.
    
USAGE: %(PROG)s CERT <cnf file> [--csr=<CSR>] [--name=<common name>] [--pgAddr=] --sign_CA=<CA> --sign_key=<CAkey>] [--self_sign=<private_key>]
    Generates a CERT and optionally signs it.
    
    If --csr is specified, the CERT is derived from the specified CSR. Otherwise,
    a new csr AND private key are automatically generated. In generating a CSR and
    key, the --name and --pgAddr options have the same behavior as for the CSR op.
    
    If sign_CA and sign_key are specified, it will be signed by the CA
    
    If self_sign is specified, it will be signed by the private key. If a private
    key is auto generated (e.g., because --csr is NOT specified) --self-sign
    does not require an argument
    
USAGE: %(PROG)s SIGN <CA> <CAkey> [csrs...]
    Signs one or more CSR's with the CA's cert and key.
""" % {"PROG":sys.argv[0]}
    if exit != None:
        sys.exit(exit)

def configureName(cnf, name=None, pgAddr=None):
    if name:
        cnf.loadData("req_distinguished_name",("commonName_default", name))
    elif pgAddr:
        parts = pgAddr.split(',')
        if len(parts) not in range(1,5):
            usage(exit=-1)
        for i in range(len(parts)):
            key = 'BLOCK%d' % (4-i) # Start at BLOCK4, then BLOCK3
            v = parts[-(i+1)] # start with last part, then second
            cnf.loadData("playground", (key, v))
    
    if not name:
        createCommonNameFromPlaygroundAddr(cnf)

if __name__ == "__main__":
    progname, args = sys.argv[0], sys.argv[1:]
    if not args:
        usage(exit=-1)
        
    opType = args.pop(0)
    if "--help" == opType:
        usage(exit=0)
        
    cnf = Cnf()
    i = 0
    opts = {}
    for arg in args:
        if arg[0] == "-":
            if '=' in arg:
                k,v = arg.split("=")
                opts[k] = v
            else:
                opts[arg] = True
        else:
            opts[i] = arg
            i+=1
    
    if "KEY" == opType:
        keyFileName = opts.get(0, None)
        cnfFile = opts.get(1, None)
        if not keyFileName:
            usage(exit=-1)
        if cnfFile: 
            with open(cnfFile) as f:
                cnf.loadText(f.read())
        genKey(keyFileName, cnf)
        print "Key created and saved in", keyFileName
        sys.exit(0)
        
    elif "CSR" == opType:
        cnfFile = opts.get(0, None)
        keyFile = opts.get("--key",None)
        name = opts.get("--name",None)
        pgAddr = opts.get("--pgAddr", None)
        
        if not cnfFile or (name and pgAddr):
            usage(exit=-1)
        with open(cnfFile) as f:
            cnf.loadText(f.read())
        configureName(cnf, name, pgAddr)
        if not keyFile:
            name = cnf["req_distinguished_name"]["commonName_default"]
            keyFile = "%s.key" % name.replace(' ','_')
            genKey(keyFile, cnf)
        csrName = genCSR(keyFile, cnf)
        print "Generated", csrName
        sys.exit(0)
        
    elif "CERT" == opType:
        cnfFile = opts.get(0, None)
        selfSign = opts.get('--self-sign',False)
        CA = opts.get('--sign_CA',None)
        CAkey = opts.get('--sign_key',None)
        eraseCsr = False
        if not cnfFile:
            usage(exit=-1)
        with open(cnfFile) as f:
            cnf.loadText(f.read())
        csrFile = opts.get('--csr', None)
        if not csrFile:
            name = opts.get('--name',None)
            pgAddr = opts.get('--pgAddr',None)
            configureName(cnf, name, pgAddr)
            name = cnf['req_distinguished_name']['commonName_default']
            keyFile = "%s.key" % name.replace(" ","_")
            genKey(keyFile, cnf)
            print "Generated private key", keyFile
            csrFile = genCSR(keyFile, cnf)
            if selfSign:
                privateKeyFile = keyFile
            else:
                privateKeyFile = None
            eraseCsr = True
        elif selfSign:
            privateKeyFile = selfSign
        else:
            privateKeyFile = None
        certName = genCert(csrFile, cnf, privateKeyFile, CA, CAkey, eraseCsr)
        print "Generated cert", certName
        sys.exit(0)
    
    elif "SIGN" == opType:
        CA = opts.get(0,None)
        CAkey = opts.get(1, None)
        if not CA or not CAkey:
            usage(exit=-1)
        i = 2
        while opts.get(i,None):
            signCSR(opts[i], CA, CAkey)
            i+=1
        sys.exit(0)
    
    usage(exit=-1)
