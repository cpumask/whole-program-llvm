import os
import shutil

local_configs = {}
config_loaded = False

# Get a specific configuration parameter, try the following sources
# (1) environment variables
# (2) a local config file located within the same folder as this script
def getarg(name):
    v = os.getenv(name)
    if v:
        return v
    #Then try the locao config, if any
    global local_configs, config_loaded
    if not config_loaded:
        load_local_config()
    return local_configs.get(name, None)

def strip_quotes(s):
    s = s.strip()
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        s = s[1:-1]
    return s

def load_local_config():
    global config_loaded, local_configs
    if config_loaded:
        return
    config_loaded = True
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(cur_dir, "wconfig")
    try:
        with open(config_path, "r") as f:
            for ln in f:
                if not ln.startswith("export"):
                    pass
                ind = ln.find("=")
                if ind < 8:
                    pass
                k = ln[7:ind]
                v = strip_quotes(ln[ind + 1:])
                local_configs[k] = v
    except FileNotFoundError:
        pass

def trimBCPath(p):
    for i in range(len(p)):
        if p[i] not in ('.', '/'):
            return p[i:]
    return ''

def copyBC(bcPath):
    # loicg: If the environment variable WLLVM_BC_STORE is set, copy the bitcode
    # file to that location, using a hash of the original bitcode path as a name
    storeEnv = getarg('WLLVM_BC_STORE')
    if storeEnv:
        #hashName = getHashedPathName(absBcPath)
        #copyfile(absBcPath, os.path.join(storeEnv, hashName))
        absBcPath = os.path.abspath(bcPath)
        subPath = trimBCPath(bcPath)
        dstPath = os.path.join(storeEnv, subPath)
        # Ensure the destination directory exists
        os.makedirs(os.path.dirname(dstPath), exist_ok=True)
        shutil.copyfile(absBcPath, dstPath)