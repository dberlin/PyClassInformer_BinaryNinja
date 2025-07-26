"""
PyClassInformer - Binary Ninja Plugin
Yet Another RTTI Parser for Binary Ninja

Converted from IDA Pro plugin to Binary Ninja
Original Author: [Original Author]
Binary Ninja Port: [Your Name]
"""

import os
import sys
from binaryninja import *

# Add plugin directory to path
plugin_dir = os.path.dirname(os.path.abspath(__file__))
if plugin_dir not in sys.path:
    sys.path.insert(0, plugin_dir)

from pyclassinformer import pyclassinformer_bn

def run_pyclassinformer(bv):
    """Main entry point for PyClassInformer (with default settings)"""
    try:
        pyclassinformer_bn.run_pci_simple(bv)
    except Exception as e:
        log_error(f"PyClassInformer error: {str(e)}")
        raise

def run_pyclassinformer_with_config(bv):
    """Main entry point for PyClassInformer with configuration dialog"""
    try:
        pyclassinformer_bn.run_pci_with_config(bv)
    except Exception as e:
        log_error(f"PyClassInformer error: {str(e)}")
        raise

# Register the plugins
PluginCommand.register(
    "PyClassInformer",
    "Parse MSVC RTTI structures and display class hierarchies (default settings)",
    run_pyclassinformer
)

PluginCommand.register(
    "PyClassInformer\\Configure and Run",
    "Parse MSVC RTTI structures with configuration dialog",
    run_pyclassinformer_with_config
)