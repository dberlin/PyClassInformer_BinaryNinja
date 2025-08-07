"""
PyClassInformer function colors for Binary Ninja
Binary Ninja equivalent of get_func_colors.py from IDA version
"""

import binaryninja as bn
from binaryninja import log_info, log_warn, log_error

def get_libfunc(bv):
    """Get a library function for color sampling - BN equivalent"""
    for func in bv.functions:
        # Check if function has library tag or appears to be a library function
        if func.name.startswith("_") or func.name.startswith("__"):
            return func
        # Check for common library patterns
        if any(pattern in func.name.lower() for pattern in ["std::", "malloc", "free", "printf", "strlen"]):
            return func
    return None

def get_genfunc(bv):
    """Get a general (user) function for color sampling - BN equivalent"""
    for func in bv.functions:
        # Look for user functions (not library, not thunks)
        if not func.name.startswith("_") and not func.name.startswith("sub_"):
            # Check if it's not obviously a library function
            if not any(pattern in func.name.lower() for pattern in ["std::", "malloc", "free", "printf", "strlen"]):
                return func
        # Also accept sub_ functions as they're likely user code
        if func.name.startswith("sub_"):
            return func
    return None

def get_gen_lib_func_colors():
    """
    Get general and library function colors - BN equivalent
    Note: Binary Ninja doesn't have the same color system as IDA,
    so we return default colors that work well with Binary Ninja's UI
    """
    try:
        # Binary Ninja uses different color schemes
        # These are reasonable defaults that work in both light and dark themes
        gen_func_color = 0xffffffff  # White/default for general functions
        lib_func_color = 0xffffffe9  # Light yellow for library functions
        
        # For dark theme compatibility
        # Note: Binary Ninja automatically adjusts colors for dark themes
        # so we don't need complex theme detection like the IDA version
        
        log_info(f"Using function colors - General: 0x{gen_func_color:x}, Library: 0x{lib_func_color:x}")
        
    except Exception as e:
        log_warn(f"Error getting function colors: {e}")
        # Fallback colors
        gen_func_color = 0xffffffff
        lib_func_color = 0xffffffe9
    
    return gen_func_color, lib_func_color

# For testing/debugging
def test_func_colors(bv):
    """Test function to verify color detection works"""
    gen_func = get_genfunc(bv)
    lib_func = get_libfunc(bv)
    
    log_info(f"Sample general function: {gen_func.name if gen_func else 'None found'}")
    log_info(f"Sample library function: {lib_func.name if lib_func else 'None found'}")
    
    gen_color, lib_color = get_gen_lib_func_colors()
    log_info(f"General function color: 0x{gen_color:x}")
    log_info(f"Library function color: 0x{lib_color:x}")