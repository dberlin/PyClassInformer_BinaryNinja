"""
PyClassInformer library classes checker for Binary Ninja
Identifies standard library classes (STL, MFC, etc.) - complete IDA equivalent
"""

import os
import json
import re
from binaryninja import log_info, log_warn, log_error

class lib_classes_checker_t(object):
    """Library classes checker - identical to IDA version"""
    
    def __init__(self, rules=None):
        if rules is None:
            rules = os.path.join(os.path.dirname(__file__), "lib_classes.json")
        self.lib_class_ptns = {}
        try:
            with open(rules) as f:
                self.lib_class_ptns = json.load(f)
        except Exception as e:
            log_error(f"Failed to load library class patterns from {rules}: {e}")
            # Default patterns if file loading fails
            self.lib_class_ptns = {
                "=": [],
                "startswith": ["std::", "boost::", "ATL::", "CWin", "CMF"],
                "regex": []
            }
            
    def does_class_startwith(self, name, ptns):
        """Check if class name starts with any pattern"""
        for ptn in ptns:
            if name.startswith(ptn):
                return True
        return False
    
    def does_class_match_regex_ptns(self, name, ptns):
        """Check if class name matches any regex pattern"""
        for ptn in ptns:
            try:
                if re.match(ptn, name):
                    return True
            except re.error as e:
                log_warn(f"Invalid regex pattern '{ptn}': {e}")
        return False
    
    def is_class_lib(self, name):
        """Check if class is a library class - identical to IDA version"""
        if not name:
            return False
            
        r = False
        if name in self.lib_class_ptns.get("=", []):
            r = True
        elif self.does_class_startwith(name, self.lib_class_ptns.get("startswith", [])):
            r = True
        elif self.does_class_match_regex_ptns(name, self.lib_class_ptns.get("regex", [])):
            r = True
        return r

def set_libflag(data):
    """Set library flags for RTTI classes - identical to IDA version"""
    if not data:
        return
        
    lib_checker = lib_classes_checker_t()
    
    for vftable_ea in data:
        col = data[vftable_ea]
        
        # get the class name that owns the vftable
        class_name = col.name
        if not class_name:
            continue
        
        # check the class is a part of standard library classes such as STL and MFC
        col.libflag = col.LIBNOTLIB
        if lib_checker.is_class_lib(class_name):
            col.libflag = col.LIBLIB
            log_info(f"Marked {class_name} as library class")

# Test functionality (commented out)
"""
lib_class_ptns = lib_classes_checker_t()
print(lib_class_ptns.is_class_lib("std::exception"))  # True
print(lib_class_ptns.is_class_lib("CWinApp"))  # True  
print(lib_class_ptns.is_class_lib("CSimpleTextApp"))  # False
"""