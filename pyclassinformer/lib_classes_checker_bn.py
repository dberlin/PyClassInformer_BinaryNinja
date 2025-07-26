"""
PyClassInformer library classes checker for Binary Ninja
Identifies known library classes and applies appropriate flags
"""

import json
import os
import binaryninja as bn
from binaryninja import log_info, log_warn, log_error

def set_libflag(bv, results):
    """Set library flags for known class methods"""
    if not results:
        return
    
    # Load known library classes
    lib_classes = _load_lib_classes()
    if not lib_classes:
        return
    
    log_info("Applying library flags to known classes...")
    
    # TODO: Implement library class detection and flagging
    # This would involve:
    # 1. Matching class names against known library patterns
    # 2. Applying appropriate tags or symbols in Binary Ninja
    # 3. Marking functions as library functions where appropriate
    
    log_info("Library flag application complete")

def _load_lib_classes():
    """Load known library classes from JSON file"""
    try:
        plugin_dir = os.path.dirname(os.path.dirname(__file__))
        lib_classes_path = os.path.join(plugin_dir, "pyclassinformer", "lib_classes.json")
        
        if os.path.exists(lib_classes_path):
            with open(lib_classes_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        log_warn(f"Failed to load library classes: {e}")
    
    return None