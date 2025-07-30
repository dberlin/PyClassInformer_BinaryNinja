try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

class pci_config(object):
    
    alldata = True
    rtti = True
    exana = True
    mvvm = True
    mvcd = True
    rnvm = True
    rncd = True
    dirtree = True
    
    def __init__(self, alldata=False, rtti=True, exana=True, mvvm=True, mvcd=True, rnvm=True, rncd=True):
        self.alldata = alldata
        self.rtti = rtti
        self.exana = exana
        self.mvvm = mvvm
        self.mvcd = mvcd
        self.rnvm = rnvm
        self.rncd = rncd
        self.check_dirtree()
        
    def check_dirtree(self):
        # Check if we're running in Binary Ninja or IDA
        try:
            import binaryninja
            # Running in Binary Ninja - we have our own tree implementation
            self.dirtree = True  # We support tree view via Binary Ninja tags
            # Keep other options as they were set in __init__
        except ImportError:
            # Running in IDA - check for ida_dirtree
            try:
                import ida_dirtree
                ida_dirtree.dirtree_t.find_entry
                self.dirtree = True
            # for IDA 7.x
            except (ModuleNotFoundError, AttributeError) as e:
                self.exana = False
                self.mvvm = False
                self.mvcd = False
                self.dirtree = False
            
