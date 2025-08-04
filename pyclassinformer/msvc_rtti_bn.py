"""
MSVC RTTI Parser for Binary Ninja
Complete port of IDA functionality to Binary Ninja API
"""

import struct
import binaryninja as bn
from binaryninja import log_info, log_warn, log_error, log_debug
from . import pci_utils_bn

# Binary Ninja utilities instance
u = None

class RTTIStruc(object):
    """Base class for RTTI structures"""
    size = 0
    
    def __init__(self):
        self.size = 0

def strip(name):
    """Strip RTTI decoration from type names"""
    if name.startswith("class ") and name.endswith("`RTTI Type Descriptor'"):
        return name[6:-23]
    elif name.startswith("struct ") and name.endswith("`RTTI Type Descriptor'"):
        return name[7:-23]
    else:
        return name

class RTTITypeDescriptor(RTTIStruc):
    """RTTI Type Descriptor structure parser - identical to IDA version"""
    
    # Class-level size (will be set after structure creation)
    size = 16  # Base size, will be updated per instance
    
    def __init__(self, ea):
        global u
        if u is None:
            log_error("Utils not initialized")
            return
            
        self.class_name = None
        self.ea = ea
        
        # Calculate name address
        name_offset = u.PTR_SIZE * 2  # pVFTable + spare
        name_addr = ea + name_offset
        
        # Get string length
        strlen = u.get_strlen(name_addr)
        if strlen is None:
            # Not a real type descriptor
            return
            
        self.size = name_offset + strlen + 1  # +1 for NULL byte
        
        # Get mangled name
        mangled = u.get_string(name_addr, strlen)
        if not mangled:
            # Not a real function name
            return
        
        # Get demangled name using Binary Ninja's demangling
        demangled_name = self._demangle_name(mangled)
        if demangled_name:
            # Create and apply structure type
            self._create_struct_type()
            self.class_name = demangled_name
            return
    
    def _demangle_name(self, mangled):
        """Demangle MSVC mangled name using Binary Ninja's demangler"""
        if not mangled.startswith('.'):
            log_info(f"Mangled name doesn't start with dot: '{mangled}'")
            return None
            
        try:
            log_info(f"Attempting to demangle: '{mangled}'")
            
            # Get the architecture for demangling
            arch = u.bv.arch
            
            # The mangled name is already a type descriptor name, try it directly first
            demangled_types = bn.demangle_ms(arch, mangled)
            log_info(f"Direct demangling result: {demangled_types}")
            if demangled_types and len(demangled_types) > 0:
                result = str(demangled_types[0])
                log_info(f"Direct demangling succeeded: '{result}'")
                return result
            
            # Try constructing full RTTI type descriptor symbol like IDA version
            full_symbol = '??_R0' + mangled[1:]
            log_info(f"Trying full RTTI symbol: '{full_symbol}'")
            demangled_types = bn.demangle_ms(arch, full_symbol)
            log_info(f"Full symbol demangling result: {demangled_types}")
            if demangled_types and len(demangled_types) > 0:
                result = str(demangled_types[0])
                log_info(f"Full symbol demangling succeeded: '{result}'")
                return result
            
            # Try without the leading dot
            no_dot = mangled[1:]
            log_info(f"Trying without dot: '{no_dot}'")
            demangled_types = bn.demangle_ms(arch, no_dot)
            log_info(f"No dot demangling result: {demangled_types}")
            if demangled_types and len(demangled_types) > 0:
                result = str(demangled_types[0])
                log_info(f"No dot demangling succeeded: '{result}'")
                return result
                
        except Exception as e:
            log_info(f"Demangling exception for '{mangled}': {e}")
        
        log_info(f"All demangling attempts failed for: '{mangled}'")
        return None
    
    def _create_struct_type(self):
        """Create RTTITypeDescriptor structure type"""
        if not u:
            return
            
        # Create structure members exactly like IDA version
        members = [
            ("pVFTable", bn.Type.pointer(u.bv.arch, bn.Type.void()), u.PTR_SIZE),
            ("spare", bn.Type.pointer(u.bv.arch, bn.Type.void()), u.PTR_SIZE),
            ("name", bn.Type.array(bn.Type.char(), self.size - u.PTR_SIZE * 2), self.size - u.PTR_SIZE * 2)
        ]
        
        struct_type = u.create_struct_type(f"RTTITypeDescriptor_{self.ea:x}", members)
        if struct_type:
            u.apply_struct_type(self.ea, f"RTTITypeDescriptor_{self.ea:x}")

class RTTIClassHierarchyDescriptor(RTTIStruc):
    """RTTI Class Hierarchy Descriptor - identical to IDA version"""
    
    CHD_MULTINH   = 0x01  # Multiple inheritance
    CHD_VIRTINH   = 0x02  # Virtual inheritance  
    CHD_AMBIGUOUS = 0x04  # Ambiguous inheritance
    
    size = 16  # Fixed size: 4 DWORDs
    
    def __init__(self, ea):
        global u
        if u is None:
            return
            
        self.ea = ea
        self.sig = 0
        self.bcaea = 0
        self.nb_classes = 0
        self.flags = ""
        self.bca = None
        
        # Read structure data
        data = u.bv.read(ea, self.size)
        if not data or len(data) < self.size:
            return
            
        try:
            # Unpack exactly like IDA version
            self.sig = u.get_dword(ea)
            self.attribute = u.get_dword(ea + 4)
            self.nb_classes = u.get_dword(ea + 8)
            bca_rva = u.get_dword(ea + 12)
            
            # Convert RVA to VA like IDA version
            self.bcaea = bca_rva + u.x64_imagebase()
            
            # Create BCA exactly like IDA
            self.bca = RTTIBaseClassArray(self.bcaea, self.nb_classes)
            
            # Parse attribute flags exactly like IDA
            if self.attribute & self.CHD_MULTINH:
                self.flags += "M"
            if self.attribute & self.CHD_VIRTINH:
                self.flags += "V"
            if self.attribute & self.CHD_AMBIGUOUS:
                self.flags += "A"
            
            # Create structure type
            self._create_struct_type()
            log_debug(f"Found CHD at 0x{ea:x}: {self.nb_classes} classes, flags: {self.flags}")
            
        except Exception as e:
            log_debug(f"Failed to parse CHD at 0x{ea:x}: {e}")
    
    def _create_struct_type(self):
        """Create RTTIClassHierarchyDescriptor structure type"""
        members = [
            ("signature", bn.Type.int(4), 4),
            ("attribute", bn.Type.int(4), 4),
            ("numBaseClasses", bn.Type.int(4), 4),
            ("pBaseClassArray", bn.Type.int(4), 4)
        ]
        
        struct_type = u.create_struct_type(f"RTTIClassHierarchyDescriptor_{self.ea:x}", members)
        if struct_type:
            u.apply_struct_type(self.ea, f"RTTIClassHierarchyDescriptor_{self.ea:x}")

class RTTIBaseClassDescriptor(RTTIStruc):
    """RTTI Base Class Descriptor - identical to IDA version"""
    
    BCD_NOTVISIBLE = 0x00000001
    BCD_AMBIGUOUS = 0x00000002
    BCD_PRIVORPROTBASE = 0x00000004
    BCD_PRIVORPROTINCOMPOBJ = 0x00000008
    BCD_VBOFCONTOBJ = 0x00000010
    BCD_NONPOLYMORPHIC = 0x00000020
    BCD_HASPCHD = 0x00000040  # pClassDescriptor field is present
    
    # Size calculation like IDA
    size = 28  # Base size, may vary
    
    def __init__(self, ea):
        global u
        if u is None:
            return
            
        self.ea = ea
        self.tdea = 0
        self.chdea = 0
        self.name = ""
        self.depth = 0
        self.nb_cbs = 0
        self.mdisp = 0
        self.pdisp = 0
        self.vdisp = 0
        self.attributes = 0
        
        # Validate memory before parsing
        if not u.is_valid_addr(ea):
            return
            
        try:
            # Read structure data first to determine size
            data = u.bv.read(ea, 28)  # Max possible size
            if not data or len(data) < 24:  # Minimum size
                return
            
            # Read structure exactly like IDA version
            self.tdea = u.get_dword(ea) + u.x64_imagebase()
            self.nb_cbs = u.get_dword(ea + 4)
            self.mdisp = u.get_signed_dword(ea + 8)
            self.pdisp = u.get_signed_dword(ea + 12)
            self.vdisp = u.get_signed_dword(ea + 16)
            self.attributes = u.get_dword(ea + 20)
            
            # Handle pClassDescriptor if present (like IDA)
            if self.attributes & self.BCD_HASPCHD:
                if len(data) >= 28:  # Ensure we have enough data
                    self.chdea = u.get_dword(ea + 24) + u.x64_imagebase()
                    self.size = 28
                else:
                    # Inconsistent data - has flag but not enough bytes
                    return
            else:
                self.chdea = 0
                self.size = 24
            
            # Validate TypeDescriptor address before accessing
            if not u.is_valid_addr(self.tdea):
                return
            
            # Get type descriptor to extract name (like IDA)
            td = RTTITypeDescriptor(self.tdea)
            if td.class_name:
                self.name = strip(td.class_name)
                # Apply structure type after successful parsing
                self._create_struct_type()
                log_debug(f"Found BCD at 0x{ea:x}: {self.name}")
            else:
                # TypeDescriptor parsing failed - invalid BCD
                return
            
        except Exception as e:
            log_debug(f"Failed to parse BCD at 0x{ea:x}: {e}")
            return
    
    def _create_struct_type(self):
        """Create RTTIBaseClassDescriptor structure type"""
        members = [
            ("pTypeDescriptor", bn.Type.int(4), 4),
            ("numContainerBases", bn.Type.int(4), 4),
            ("mdisp", bn.Type.int(4), 4),
            ("pdisp", bn.Type.int(4), 4),
            ("vdisp", bn.Type.int(4), 4),
            ("attributes", bn.Type.int(4), 4)
        ]
        
        if self.attributes & self.BCD_HASPCHD:
            members.append(("pClassDescriptor", bn.Type.int(4), 4))
        
        struct_type = u.create_struct_type(f"RTTIBaseClassDescriptor_{self.ea:x}", members)
        if struct_type:
            u.apply_struct_type(self.ea, f"RTTIBaseClassDescriptor_{self.ea:x}")

class RTTIBaseClassArray(RTTIStruc):
    """RTTI Base Class Array - identical to IDA version"""
    
    def __init__(self, ea, nb_classes):
        global u
        if u is None:
            return
            
        self.ea = ea
        self.nb_classes = nb_classes
        self.size = nb_classes * 4  # Array of 32-bit RVAs
        self.bases = []
        self.paths = {}
        
        if nb_classes <= 0 or nb_classes > 100:  # Sanity check like IDA
            return
        
        if not u.is_valid_addr(ea):
            return
        
        try:
            # Read array of RVAs exactly like IDA
            for i in range(nb_classes):
                rva_addr = ea + (i * 4)
                rva = u.get_dword(rva_addr)
                if rva == 0:
                    continue
                
                bcd_va = rva + u.x64_imagebase()
                if u.is_valid_addr(bcd_va):
                    bcd = RTTIBaseClassDescriptor(bcd_va)
                    if bcd.name:  # Valid BCD
                        self.bases.append(bcd)
            
            self._create_struct_type()
            log_debug(f"Found BCA at 0x{ea:x}: {len(self.bases)} valid BCDs")
            
        except Exception as e:
            log_debug(f"Failed to parse BCA at 0x{ea:x}: {e}")
    
    def _create_struct_type(self):
        """Create RTTIBaseClassArray structure type"""
        array_type = bn.Type.array(bn.Type.int(4), self.nb_classes)
        type_name = f"RTTIBaseClassArray_{self.ea:x}"
        
        try:
            u.bv.define_user_type(type_name, array_type)
            u.bv.define_user_data_var(self.ea, bn.Type.named_type_from_type(type_name, array_type))
        except:
            pass
    
    def fix_offset(self, col_offs, curr_path, curr_off):
        """Fix offset for multiple inheritance paths - from IDA version"""
        # for MI with multiple vftables
        if len(col_offs) > 1:
            if curr_path and curr_path[-1].mdisp in col_offs:
                return curr_path[-1].mdisp
            return curr_off
        # for other cases such as SI and MI with a single vftable
        return sorted(col_offs)[0]
    
    def is_path_added(self, curr_path, offset, vi_offs, col):
        """Check if path should be added - from IDA version"""
        # if the offset has negative value, the path will not be added
        if offset < 0:
            return False
        
        # if the path does not have any VI classes, it will be added.
        if len(vi_offs) == 0:
            return True
        
        # if the path has a VI class and the path is for the current COL, the path will be added.
        if col.offset in vi_offs:
            # here, it needs to compare the names instead of instances
            # because they are different on each vftable
            if [x.name for x in vi_offs[col.offset]] == [x.name for x in curr_path]:
                return True
        return False
    
    def fix_offset_final(self, col_offs, curr_path, curr_off, vi_offs, col):
        """Calculate final offset mainly for VI - from IDA version"""
        # get first VI class
        found = False
        bcd = None
        for bcd in curr_path:
            if bcd.pdisp >= 0:
                found = True
                break
            
        # for SI and MI
        if len(col_offs) <= 1 or not found:
            return curr_off
        
        # for VI
        if found:
            found_col = False
            # get current offset if the current col is already in vi_offs.
            if col.offset in vi_offs:
                curr_off = col.offset
            # if the current col offset is not in vi_offs, the path is not processed yet.
            else:
                for p in vi_offs:
                    # check vi_offs table to get the correct offset by comparing the current
                    # path and paths in the vi_offs.
                    # here, it needs to compare the names instead of instances because they
                    # are different on each vftable
                    if [x.name for x in vi_offs[p]] == [x.name for x in curr_path]:
                        # sometimes, a class has two or more vftables, and a vfptr is at
                        # its COL's offset but anther is not at COL's offsets because of VI.
                        # E.g.
                        # XXXXX::xxx (0,-1,0) -> XXXXX::yyy (0,4,4)
                        # in this case, the current path is necessary on both vftables.
                        # here, a path that is already added in the past will also be added
                        # to another vftable that is not stored in vi_offs yet.
                        if curr_off in col_offs and col.offset != curr_off:
                            pass
                        # otherwise, this path will be skipped adding the current vftable
                        # because it is already processed.
                        else:
                            return -1
                    else:
                        # processing the path is the first time.
                        # this path will be added on the current vftable.
                        pass
                
                # update vi_offs if the offset is empty, processing the path is the first 
                # time, or a special case (see above)
                curr_off = col.offset
                vi_offs[col.offset] = curr_path
                found_col = True

            if not found_col:
                if curr_off not in vi_offs:
                    log_warn(f"Warning: current offset {curr_off} was not found in vi_offs table {vi_offs}. This should be a virtual inheritance {[x.name for x in curr_path]}.")
        else:
            log_warn(f"Warning: current offset {curr_off} is not in COL's offset {col_offs}. This should be a virtual inheritance. But all pdisp values in the path has negative values. {[x.pdisp for x in curr_path]} {[x.name for x in curr_path]}")
        return curr_off

    def parse_bca(self, col, col_offs, vi_offs):
        """Parse BCA hierarchy - full implementation from IDA version"""
        ea = self.ea
        nb_classes = self.nb_classes
        
        # Clear existing bases and rebuild them
        self.bases = []
        
        # parse bca
        for i in range(0, nb_classes):
            bcdoff = ea + i*4
            
            # get relevant structures
            bcdea = u.get_dword(bcdoff) + u.x64_imagebase()
            if not u.is_valid_addr(bcdea):
                continue
                
            bcd = RTTIBaseClassDescriptor(bcdea)
            if not bcd.name:
                continue
                
            # Add to bases list
            self.bases.append(bcd)
                
        # parse hierarchy
        result_paths = {}
        curr_path = []
        n_processed = {}
        curr_off = 0
        
        for i, bcd in enumerate(self.bases):
            n_processed[bcd.nb_cbs] = 0
            
            # add BCD to the current path
            curr_path.append(bcd)
            curr_depth = len(curr_path) - 1
            
            # update the offset for paths of base classes
            curr_off = self.fix_offset(col_offs, curr_path, curr_off)
        
            # find a path to an offset for multiple inheritance
            if bcd.nb_cbs == 0:
                path = curr_path.copy()
                
                # get the final offset mainly for VI
                offset = self.fix_offset_final(col_offs, path, curr_off, vi_offs, col)
                
                # append result according to the obtained offset
                if self.is_path_added(path, offset, vi_offs, col):
                    if offset in result_paths:
                        result_paths[offset].append(path)
                    else:
                        result_paths[offset] = [path]
                    
                # rewind current result for next inheritance
                while True:
                    # compare the number of bases to be processed in the current path with the number processed so far.
                    # if they are matched, the base class must have been processed. So remove it.
                    if n_processed[curr_path[-1].nb_cbs] == curr_path[-1].nb_cbs:
                        # pop the record of the last bcd from the n_processed. and pop the last bcd itself from the current path.
                        del n_processed[curr_path[-1].nb_cbs]
                        prev_bcd = curr_path.pop()
                        
                        # set the number processed so far to the new tail.
                        if len(curr_path) > 0:
                            n_processed[curr_path[-1].nb_cbs] += prev_bcd.nb_cbs + 1
                            
                    # quit the loop if finished, or no need to unwind for next bcd.
                    if len(curr_path) == 0 or (len(curr_path) > 0 and n_processed[curr_path[-1].nb_cbs] != curr_path[-1].nb_cbs):
                        break
            
            yield bcd, curr_depth
            
            # update the base class depth
            self.bases[i].depth = curr_depth
                        
        self.paths = result_paths

        if col.offset not in self.paths or not self.paths[col.offset]:
            log_warn(f"Warning: Dispatching class hierarchy paths of the BCA at {ea:#x} for {self.bases[0].name if self.bases else 'unknown'} may be wrong because the paths list for the offset {col.offset} is empty. The paths will be misclassified as the wrong offset.")

class RTTICompleteObjectLocator(RTTIStruc):
    """RTTI Complete Object Locator - identical to IDA version"""
    
    # Size depends on architecture like IDA
    size = 20  # Base size for x86, will be adjusted
    
    LIBUNK = 0
    LIBLIB = 1
    LIBNOTLIB = 2
    
    def __init__(self, ea, vtable):
        global u
        if u is None:
            return
            
        self.ea = ea
        self.name = None
        self.chd = None
        self.td = None
        self.offset = 0
        self.cdOffset = 0
        self.vfeas = []
        self.libflag = self.LIBUNK
        self.selfea = 0
        
        # Adjust size for x64 like IDA
        if u.x64:
            self.size = 24
        else:
            self.size = 20
        
        if not u.is_valid_addr(ea):
            return
            
        try:
            # Read COL members exactly like IDA version
            self.sig = u.get_dword(ea)
            self.offset = u.get_dword(ea + 4)
            self.cdOffset = u.get_dword(ea + 8)
            self.tdea = u.get_dword(ea + 12) + u.x64_imagebase()
            self.chdea = u.get_dword(ea + 16) + u.x64_imagebase()
            
            if u.x64:
                self.selfea = u.get_dword(ea + 20) + u.x64_imagebase()
            else:
                self.selfea = 0
            
            # Validate signature (should be 0 or 1 for valid COL)
            if self.sig > 1:
                return
            
            # Get TD to get the class name exactly like IDA
            if u.is_valid_addr(self.tdea):
                td = RTTITypeDescriptor(self.tdea)
                if td.class_name:
                    # Parse relevant structures like IDA
                    self.td = td
                    if u.is_valid_addr(self.chdea):
                        self.chd = RTTIClassHierarchyDescriptor(self.chdea)
                    
                    # Get virtual function addresses like IDA
                    self.vfeas = get_vtbl_methods(vtable)
                    
                    # Set class name like IDA
                    self.name = strip(self.td.class_name)
                    
                    # Set vftable name like IDA
                    current_name = u.get_name(vtable)
                    if not current_name or current_name.startswith("data_"):
                        u.set_name(vtable, f"vtable__{self.name}")
                    
                    self._create_struct_type()
                    return
            
        except Exception as e:
            log_info(f"Failed to parse COL at 0x{ea:x}: {e}")
    
    
    def _create_struct_type(self):
        """Create RTTICompleteObjectLocator structure type"""
        members = [
            ("signature", bn.Type.int(4), 4),
            ("offset", bn.Type.int(4), 4),
            ("cdOffset", bn.Type.int(4), 4),
            ("pTypeDescriptor", bn.Type.int(4), 4),
            ("pClassDescriptor", bn.Type.int(4), 4)
        ]
        
        if u.x64:
            members.append(("pSelf", bn.Type.int(4), 4))
        
        struct_type = u.create_struct_type(f"RTTICompleteObjectLocator_{self.ea:x}", members)
        if struct_type:
            u.apply_struct_type(self.ea, f"RTTICompleteObjectLocator_{self.ea:x}")

class rtti_parser(object):
    """Main RTTI parser - identical to IDA version functionality"""
    
    @staticmethod
    def parse(start, end):
        """Parse RTTI structures in memory range - identical to IDA version"""
        global u
        if u is None:
            return {}
        
        data_size = end - start
        log_info(f"Parsing RTTI from 0x{start:x} to 0x{end:x} (size: {data_size} bytes)")
        
        # Get COLs with CHDs and TDs - improved approach
        result = {}
        addresses_checked = 0
        potential_cols = 0
        valid_rtti_found = 0
        
        # Scan for potential COL pointers within valid ranges first
        for offset in range(0, data_size - u.PTR_SIZE, u.PTR_SIZE):
            vtable = start + offset
            addresses_checked += 1
            
            # Read the potential COL address (pointer at vtable - PTR_SIZE)
            colea = u.get_ptr(vtable - u.PTR_SIZE)
            
            # Check if the COL address is within valid ranges (where COLs would be stored)
            if u.within(colea):
                potential_cols += 1
                
                # Verify vtable address is within range and looks like a vtable
                if vtable < end and rtti_parser._is_vtable(vtable):
                    if potential_cols <= 3:  # Only log first 3 to avoid spam
                        log_info(f"Found potential COL pointer 0x{colea:x} before vtable at 0x{vtable:x}")
                    
                    # Try to parse the COL structure
                    col = RTTICompleteObjectLocator(colea, vtable)
                    
                    # Add COL to results if valid
                    if col.name is not None:
                        log_info(f"Found valid RTTI class: {col.name} at COL 0x{colea:x}, vtable 0x{vtable:x}")
                        result[vtable] = col
                        valid_rtti_found += 1
                elif potential_cols <= 3:
                    log_info(f"  COL pointer 0x{colea:x} not followed by valid vtable at 0x{vtable:x}")
        
        log_info(f"Scanned {addresses_checked} addresses, found {potential_cols} potential COLs, {valid_rtti_found} valid RTTI structures")
        
        # Create lookup table for O(1) _get_col_offs - fixes O(N²) complexity
        td_chd_lookup = {}
        for vtable, col in result.items():
            key = (col.tdea, col.chdea)
            if key not in td_chd_lookup:
                td_chd_lookup[key] = []
            td_chd_lookup[key].append(col)
        
        # Parse BCA for hierarchy like IDA version
        prev_col = None
        vi_offs = {}
        
        for vtable in result:
            col = result[vtable]
            col_offs = rtti_parser._get_col_offs_optimized(col, td_chd_lookup)
            
            if prev_col and prev_col.name != col.name:
                vi_offs = {}
            
            # Get BCDs (simplified version of IDA's complex algorithm)
            if col.chd and col.chd.bca:
                for bcd, depth in col.chd.bca.parse_bca(col, col_offs, vi_offs):
                    pass
                    
            prev_col = col
        
        log_info(f"Found {len(result)} RTTI structures")
        return result
    
    @staticmethod
    def _is_vtable(vtable_addr):
        """Check if address looks like a vtable - like IDA version"""
        global u
        if not u or not u.is_valid_addr(vtable_addr):
            return False
        
        # Get first function pointer
        function_ptr = u.get_ptr(vtable_addr)
        if function_ptr == 0:
            return False
        
        # Check if it points to executable code
        if not u.is_valid_addr(function_ptr):
            return False
            
        if not u.is_executable(function_ptr):
            # Try to be more lenient - sometimes function pointers might not be marked as executable yet
            # Check if it's at least in a valid memory range
            if not u.within(function_ptr):
                return False
        
        # Check if vtable has cross-references (like IDA)
        # This might be too restrictive early in analysis
        has_refs = u.has_xref(vtable_addr)
        if not has_refs:
            # For debugging: log addresses that look like vtables but have no xrefs
            if vtable_addr % 0x1000 == 0:  # Only log every 4096th address to avoid spam
                log_debug(f"Potential vtable at 0x{vtable_addr:x} has no xrefs")
            return False
        
        return True
    
    @staticmethod 
    def _get_col_offs(col, result):
        """Get COL offsets - Binary Ninja implementation of IDA functionality"""
        if not col:
            return []
        
        # Get COLs that share the same TD and CHD (multiple inheritance detection)
        cols = []
        for vtable in result:
            other_col = result[vtable]
            if (other_col.tdea == col.tdea and other_col.chdea == col.chdea):
                cols.append(other_col)
        
        # Get the offsets from all related COLs
        col_offs = [c.offset for c in cols]
        return sorted(col_offs)
    
    @staticmethod 
    def _get_col_offs_optimized(col, td_chd_lookup):
        """Optimized COL offsets lookup - O(1) complexity using pre-built lookup table"""
        if not col:
            return []
        
        # Use pre-built lookup table for O(1) access
        key = (col.tdea, col.chdea)
        cols = td_chd_lookup.get(key, [col])
        
        # Get the offsets from all related COLs
        col_offs = [c.offset for c in cols]
        return sorted(col_offs)
    
    @staticmethod
    def is_binary_allowed(bv):
        """Check if binary is suitable for RTTI analysis - like IDA version"""
        # Check platform
        if bv.arch.name not in ['x86', 'x86_64']:
            log_warn(f"Platform not supported: {bv.arch.name}. Only supports x86 and x86_64.")
            return False
        
        # Check file format  
        if bv.view_type != 'PE':
            log_warn(f"Binary format not supported: {bv.view_type}. Only supports PE.")
            return False
        
        return True
    
    @staticmethod
    def show(result):
        """Display RTTI parsing results - identical to IDA version"""
        if not result:
            log_info("No RTTI results to display")
            return
        
        for vtable in result:
            col = result[vtable]
            log_info(f"vtable at : {hex(vtable)}")
            log_info(f"  COL at {col.ea:#x}: {col.name} {col.sig} {col.offset} {col.cdOffset} {hex(col.tdea)} {hex(col.chdea)} {hex(col.selfea) if col.selfea else ''}")
            
            if col.chd:
                log_info(f"  CHD at {col.chd.ea:#x}: {hex(col.chd.sig)} {col.chd.flags} {col.chd.nb_classes} {hex(col.chd.bcaea)}")
                
                # Show BCDs like IDA
                if col.chd.bca:
                    for bcd in col.chd.bca.bases:
                        log_info(f"    {'  ' * bcd.depth}BCD at {bcd.ea:#x}: {bcd.name} {hex(bcd.tdea)} {bcd.nb_cbs} {bcd.mdisp} {bcd.pdisp} {bcd.vdisp} {bcd.attributes} {hex(bcd.chdea) if bcd.chdea else ''}")
    
    @staticmethod
    def run(bv, alldata=False):
        """Main entry point - identical to IDA version functionality"""
        global u
        u = pci_utils_bn.utils(bv)
        
        result = {}
        
        # Check if binary is allowed like IDA version
        if not rtti_parser.is_binary_allowed(bv):
            return result
        
        # Log all available sections for debugging
        log_info(f"Available sections in binary:")
        for section_name in bv.sections:
            section = bv.get_section_by_name(section_name)
            if section:
                log_info(f"  {section_name}: 0x{section.start:x} - 0x{section.end:x} (size: {section.end - section.start} bytes, semantics: {section.semantics})")
        
        # Find vftables with relevant structures like IDA version
        if not alldata:
            # Try .rdata section first like IDA
            rdata_section = bv.get_section_by_name('.rdata')
            if rdata_section:
                log_info(f"Scanning .rdata section only")
                result = rtti_parser.parse(rdata_section.start, rdata_section.end)
            else:
                log_info(f"No .rdata section found, will scan all data sections")
        
        # If no results or alldata requested, scan all data sections like IDA
        if not result or alldata:
            log_info(f"Scanning all data sections (alldata={alldata}, current results: {len(result)})")
            data_sections = ['.rdata', '.data']
            for section_name in data_sections:
                section = bv.get_section_by_name(section_name)
                if section:
                    log_info(f"Scanning section {section_name}")
                    section_result = rtti_parser.parse(section.start, section.end)
                    result.update(section_result)
                else:
                    log_info(f"Section {section_name} not found")
        
        return result

# For backwards compatibility with existing code
def get_vtbl_methods(target_ea):
    """Get virtual table methods - Binary Ninja equivalent of IDA version"""
    global u
    if not u:
        return []
    
    orig_target_ea = target_ea
    methods = []
    
    # Get the section containing this vtable
    section = None
    for section_name in u.bv.sections:
        sect = u.bv.get_section_by_name(section_name)
        if sect and sect.start <= target_ea < sect.end:
            section = sect
            break
    
    if not section:
        return methods
    
    # Find next cross-referenced address to determine vtable end
    next_name_ea = section.end
    
    # Simple approach: look for next data with cross-references
    addr = target_ea + u.PTR_SIZE
    while addr < section.end:
        if u.has_xref(addr):
            next_name_ea = addr
            break
        addr += u.PTR_SIZE
    
    # Extract function pointers from vtable like IDA version
    current_addr = target_ea
    while current_addr < next_name_ea:
        # Get the function pointer
        func_ptr = u.get_ptr(current_addr)
        
        if func_ptr == 0:
            break
            
        # Check if it's a valid function address
        if u.is_valid_addr(func_ptr) and u.is_executable(func_ptr):
            methods.append(func_ptr)
        else:
            break
        
        current_addr += u.PTR_SIZE
        
        # Safety check - don't scan too far
        if len(methods) > 50:
            break
    
    return methods
