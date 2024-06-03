import os

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
                local_configs.setdefault(k, "").append(v)
    except FileNotFoundError:
        pass