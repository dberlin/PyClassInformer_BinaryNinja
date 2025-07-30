"""
PyClassInformer method classifier for Binary Ninja
Organizes and classifies virtual methods and class hierarchies - complete IDA equivalent
"""

import binaryninja as bn
from binaryninja import log_info, log_warn, log_error
from . import pci_utils_bn
from . import pci_config
from . import mc_tree_bn

def rename_func(bv, ea, prefix="", fn="", is_lib=False):
    """Rename function - Binary Ninja equivalent of IDA version"""
    func = bv.get_function_at(ea)
    if not func:
        return False
    
    current_name = func.name
    
    # if a virtual method is not a valid function, skip it
    if current_name is None:
        return False
    
    # rename the function name if it is a dummy name
    if current_name.startswith("sub_") or current_name.startswith("unknown_") or current_name.startswith("data_"):
        # change the function name to the specific name
        new_name = fn if fn else current_name
        if prefix:
            new_name = prefix + new_name
        
        try:
            func.name = new_name
            log_info(f"Renamed {current_name} -> {new_name}")
        except Exception as e:
            log_warn(f"Failed to rename function at 0x{ea:x}: {e}")
            return False
    
    # add library tag for Binary Ninja to recognize the function as library
    if is_lib:
        try:
            # Add library tag to the function
            func.add_tag("Library", "Standard Library Function")
            # Also add to the binary view level
            bv.add_tag(ea, "Library", "Standard Library Function")
        except Exception as e:
            log_warn(f"Failed to add library tag to function at 0x{ea:x}: {e}")
    
    return True

def rename_vftable_ref_funcs(bv, paths, data):
    """Rename functions that reference vtables (constructors/destructors) - IDA equivalent"""
    u = pci_utils_bn.utils(bv)
    
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable, which is the last entry of the path
        class_name = path[-1].name
        
        # check the class is a part of standard library classes such as STL and MFC
        is_lib = False
        if col.libflag == col.LIBLIB:
            is_lib = True
        
        # get the func eas that refer to vftables and rename them
        refs = u.get_xrefs_to(vftable_ea)
        for refea in refs:
            func = bv.get_function_at(refea)
            if func:
                rename_func(bv, func.start, class_name.split("<")[0] + "::", "possible_ctor_or_dtor", is_lib=is_lib)

def rename_funcs(bv, func_eas, prefix="", is_lib=False):
    """Rename multiple functions with prefix - IDA equivalent"""
    for ea in func_eas:
        rename_func(bv, ea, prefix, is_lib=is_lib)

def rename_vfuncs(bv, paths, data):
    """Rename virtual functions - IDA equivalent"""
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable, which is the last entry of the path
        class_name = path[-1].name
        vfunc_eas = data[vftable_ea].vfeas
        
        # check the class is a part of standard library classes such as STL and MFC
        is_lib = False
        if col.libflag == col.LIBLIB:
            is_lib = True
        
        rename_funcs(bv, vfunc_eas, class_name.split("<")[0] + "::", is_lib=is_lib)

def get_base_classes(bv, data):
    """Get base classes and inheritance paths - IDA equivalent"""
    u = pci_utils_bn.utils(bv)
    paths = {}
    
    for vftable_ea in data:
        # get COL
        col = data[vftable_ea]
        
        # get relevant BCDs mainly for multiple inheritance
        base_classes = get_col_bases(col, data, u)
        
        # reverse the path because the path is reverse ordered
        base_classes.reverse()
        paths[vftable_ea] = base_classes
    
    # sort the results by the class name and base class length
    return {x: paths[x] for x in sorted(sorted(paths, key=lambda key: [x.name for x in paths[key]]), key=lambda key: len(paths[key]))}

def get_col_bases(col, vftables, u):
    """Get COL base classes - Binary Ninja equivalent of IDA utils.get_col_bases"""
    # for checking if a class has multiple vftables or not
    col_offs = get_col_offs(col, vftables, u)
    
    bases = []
    if not col.chd or not col.chd.bca:
        return bases
        
    paths = getattr(col.chd.bca, 'paths', {})
    paths_for_offset = paths.get(col.offset, [])
    
    for path in paths_for_offset:
        append = False
        for bcd in path:
            # for SI and MI but there is only a vftable
            if len(col_offs) < 2:
                append = True
            # for MI and there are multiple vftables
            elif bcd.mdisp == col.offset:
                append = True
            elif bcd.pdisp >= 0:
                append = True
            # if append flag is enabled, append it and subsequent BCDs after it
            if append and bcd not in bases:
                bases.append(bcd)
    return bases

def get_col_offs(col, vftables, u):
    """Get COL offsets - Binary Ninja equivalent of IDA utils.get_col_offs"""
    cols = get_cols_by_col(col, vftables, u)
    # get the offsets in COLs
    col_offs = get_col_offs_by_cols(cols, u)
    return col_offs

def get_cols_by_col(col, vftables, u):
    """Get COLs by COL - Binary Ninja equivalent of IDA utils.get_cols_by_col"""
    # get offsets in COLs by finding xrefs for multiple inheritance
    x = set([xrea for xrea in u.get_xrefs_to(col.tdea)])
    # Note: In the IDA version, there's also col.tid, but that doesn't exist in our implementation
    # We'll just use tdea for now
    y = set([xrea for xrea in u.get_xrefs_to(col.tdea)])
    
    # If the target is a multi inheritance class, TD has multiple xrefs from multiple COLs
    # Here, get the COLs
    coleas = (x & y)
    cols = sorted([col for vtable_ea, col in vftables.items() if col.ea in coleas], key=lambda x: x.ea)
    return cols

def get_col_offs_by_cols(cols, u):
    """Get COL offsets by COLs - Binary Ninja equivalent"""
    # Extract offsets from COL structures
    col_offs = []
    for col in cols:
        try:
            col_offs.append(col.offset)
        except AttributeError:
            col_offs.append(0)
    return col_offs

def organize_functions_by_class(bv, paths, data):
    """Organize functions by class using Binary Ninja tags - enhanced version"""
    u = pci_utils_bn.utils(bv)
    
    for vftable_ea in paths:
        path = paths[vftable_ea]
        if not path:
            continue
        col = data[vftable_ea]
        
        # get the class name that owns the vftable
        class_name = path[-1].name
        
        # Determine if this is a library class
        is_lib = getattr(col, 'libflag', False) == col.LIBLIB if hasattr(col, 'LIBLIB') else False
        class_category = "LibraryClass" if is_lib else "UserClass"
        
        # Tag the vftable itself
        try:
            bv.add_tag(vftable_ea, "VFTable", f"Virtual function table for {class_name}")
            bv.add_tag(vftable_ea, class_category, class_name)
            # Also add hierarchy info
            if len(path) > 1:
                hierarchy_info = " -> ".join([bcd.name for bcd in reversed(path)])
                bv.add_tag(vftable_ea, "ClassHierarchy", hierarchy_info)
        except Exception as e:
            log_warn(f"Failed to add VFTable tags at 0x{vftable_ea:x}: {e}")
        
        # Tag virtual functions with enhanced information
        for i, vfea in enumerate(col.vfeas):
            func = bv.get_function_at(vfea)
            if func:
                try:
                    # Primary tags
                    func.add_tag("VirtualMethod", f"Virtual method of {class_name}")
                    func.add_tag(class_category, class_name)
                    bv.add_tag(vfea, "VirtualMethod", f"Virtual method of {class_name}")
                    bv.add_tag(vfea, class_category, class_name)
                    
                    # Method index tag for ordering
                    func.add_tag("MethodIndex", f"Virtual method #{i} in {class_name}")
                    
                    # Inheritance hierarchy tag
                    if len(path) > 1:
                        hierarchy_info = " -> ".join([bcd.name for bcd in reversed(path)])
                        func.add_tag("ClassHierarchy", hierarchy_info)
                        bv.add_tag(vfea, "ClassHierarchy", hierarchy_info)
                        
                except Exception as e:
                    log_warn(f"Failed to add virtual method tags at 0x{vfea:x}: {e}")
        
        # Tag constructor/destructor functions with enhanced information
        refs = u.get_xrefs_to(vftable_ea)
        for refea in refs:
            func = bv.get_function_at(refea)
            if func:
                try:
                    # Primary tags
                    func.add_tag("Constructor/Destructor", f"Possible ctor/dtor of {class_name}")
                    func.add_tag(class_category, class_name)
                    bv.add_tag(refea, "Constructor/Destructor", f"Possible ctor/dtor of {class_name}")
                    bv.add_tag(refea, class_category, class_name)
                    
                    # Inheritance hierarchy tag
                    if len(path) > 1:
                        hierarchy_info = " -> ".join([bcd.name for bcd in reversed(path)])
                        func.add_tag("ClassHierarchy", hierarchy_info)
                        bv.add_tag(refea, "ClassHierarchy", hierarchy_info)
                        
                except Exception as e:
                    log_warn(f"Failed to add ctor/dtor tags at 0x{refea:x}: {e}")
    
    log_info(f"Enhanced symbol grouping applied to {len(paths)} classes with comprehensive tags")

def method_classifier(bv, data, config=None):
    """Main method classifier - complete IDA equivalent functionality"""
    if config is None:
        config = pci_config.pci_config()
    
    if not data:
        return None
    
    # check config values to execute or not
    if not config.exana and not config.mvvm and not config.mvcd and not config.rnvm and not config.rncd:
        return None
    
    log_info("Starting method classification...")
    
    # get base classes
    paths = get_base_classes(bv, data)
    
    # rename virtual methods in vftables
    if config.rnvm:
        log_info("Renaming virtual methods...")
        rename_vfuncs(bv, paths, data)

    # rename functions that refer to vftables because they are constructors or destructors
    if config.rncd:
        log_info("Renaming constructor/destructor methods...")
        rename_vftable_ref_funcs(bv, paths, data)
    
    # organize functions by class using tags (Binary Ninja doesn't have dirtree equivalent)
    if config.mvvm or config.mvcd:
        log_info("Organizing functions by class using tags...")
        organize_functions_by_class(bv, paths, data)
    
    # display tree view (equivalent to IDA's tree display)
    tree = None
    if config.exana:
        log_info("Generating class tree view...")
        tree = mc_tree_bn.show_mc_tree_bn(bv, data, paths)
    
    log_info("Method classification complete")
    
    # Return tree for potential further operations (equivalent to returning tree in IDA)
    return tree