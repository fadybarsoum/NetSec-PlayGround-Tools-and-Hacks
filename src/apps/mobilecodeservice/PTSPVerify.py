'''
Created on Apr 7, 2014

@author: sethjn
'''

import pickle, sys

VERIFY_PICKLE_LOAD_FAILURE = 100
NOT_DIST_PATH_TUPLE_FAILURE = 101
DIST_NOT_AN_INT = 102
PATH_NOT_A_LIST = 103
ERROR_NOT_AN_EXCEPTION = 104
EVIL_DETECTED = 105

import __builtin__
import io

safe_builtins = {
    'list',
    'Exception',
    'int'
}

class DetectEvil(pickle.UnpicklingError):
    pass

class RestrictedUnpickler(pickle.Unpickler):

    def find_class(self, module, name):
        # Only allow safe classes from builtins.
        if (module == "exceptions" and name == "Exception") or (module == "__builtin__" and name in safe_builtins):
            return getattr(__builtin__, name)
        # Forbid everything else.
        raise DetectEvil("global '%s.%s' is forbidden" %
                                     (module, name))

def restricted_loads(s):
    """Helper function analogous to pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO(s)).load()

# PyPySandbox does not do return codes
def exit(msg, code, pickledObj=None):
    print "__VERIFY_RETURN_CODE__: %d" % (code,)
    print "__VERIFY_MSG__: %s" % (msg, )
    if pickledObj!=None:
        print "__VERIFY_PICKLED_OBJ__"
        print pickle.dumps(pickledObj)
    sys.exit(code)

def externalVerify(success, pickleStr):
    try:
        obj = restricted_loads(pickleStr)
    except DetectEvil, e:
        exit("Evil attempt: " + str(e), EVIL_DETECTED)
    except Exception, e:
        exit("Could not unpickle: %s" % str(e).replace("\n","-"), VERIFY_PICKLE_LOAD_FAILURE)
    if success:
        try:
            dist, path = obj
        except:
            exit("Was not dist,path tuple", NOT_DIST_PATH_TUPLE_FAILURE)
        if not type(dist) == int:
            exit("DIST not an integer", DIST_NOT_AN_INT)
        if not type(path) == list:
            exit("PATH not a list", PATH_NOT_A_LIST)
        exit("SUCCESS", 0, (dist, path))
    else:
        if not isinstance(obj, Exception):
            exit("ERROR not an exception", ERROR_NOT_AN_EXCEPTION)
        exit("SUCCESS", 0, obj)
    
    
def main():
    if len(sys.argv) != 3:
        sys.exit(-1)

    pickleFile = sys.argv[1]
    success = sys.argv[2]
    if success == "1":
        success = True
    else: success = False
    try:
        with open(pickleFile) as f:
            pickleStr = f.read()
        return externalVerify(success, pickleStr)
    except:
        pass
    
if __name__ == "__main__":
    main()