"""
PyClassInformer utilities for Binary Ninja
Provides Binary Ninja equivalents for IDA utility functions
"""

import struct
import bisect
import binaryninja as bn
from binaryninja import log_info, log_warn, log_error, log_debug

class utils(object):
    """Utility class for Binary Ninja operations"""
    
    def __init__(self, bv):
        self.bv = bv
        self.text = 0
        self.data = 0
        self.rdata = 0
        self.valid_ranges = []
        self._sorted_ranges = []  # Optimized sorted ranges for binary search
        self._range_starts = []   # Pre-computed start addresses for binary search
        
        # Architecture-specific settings
        self.x64 = bv.arch.name in ['x86_64', 'aarch64']
        self.PTR_SIZE = bv.arch.address_size
        
        # Initialize section information
        self._init_sections()
        
        # Optimize ranges for fast lookups
        self._optimize_ranges()
        
    def _init_sections(self):
        """Initialize section information"""
        # Get common sections
        text_section = self.bv.get_section_by_name('.text')
        if text_section:
            self.text = text_section.start
            self.valid_ranges.append((text_section.start, text_section.end))
        
        data_section = self.bv.get_section_by_name('.data')
        if data_section:
            self.data = data_section.start
            self.valid_ranges.append((data_section.start, data_section.end))
        
        rdata_section = self.bv.get_section_by_name('.rdata')
        if rdata_section:
            self.rdata = rdata_section.start
            self.valid_ranges.append((rdata_section.start, rdata_section.end))
        
        # Add all readable sections to valid ranges
        for section_name in self.bv.sections:
            section = self.bv.get_section_by_name(section_name)
            if section and section.semantics in [bn.SectionSemantics.ReadOnlyDataSectionSemantics,
                                               bn.SectionSemantics.ReadWriteDataSectionSemantics]:
                self.valid_ranges.append((section.start, section.end))
    
    def _optimize_ranges(self):
        """Optimize ranges for fast binary search lookups"""
        if not self.valid_ranges:
            return
        
        # Sort ranges by start address and merge overlapping ranges
        sorted_ranges = sorted(self.valid_ranges, key=lambda r: r[0])
        merged = [sorted_ranges[0]]
        
        for current in sorted_ranges[1:]:
            last = merged[-1]
            # If ranges overlap or are adjacent, merge them
            if current[0] <= last[1] + 1:
                merged[-1] = (last[0], max(last[1], current[1]))
            else:
                merged.append(current)
        
        self._sorted_ranges = merged
        self._range_starts = [r[0] for r in merged]  # Pre-compute for faster binary search
    
    def within(self, x, rl=None):
        """Check if address is within valid ranges - optimized with binary search"""
        if rl is None:
            # Use optimized sorted ranges for binary search - O(log n) instead of O(n)
            if not self._sorted_ranges:
                return False
            
            # Binary search for the range that could contain x
            # Find the rightmost range with start <= x
            idx = bisect.bisect_right(self._range_starts, x) - 1
            
            # Check if x falls within that range
            if idx >= 0 and idx < len(self._sorted_ranges):
                return self._sorted_ranges[idx][0] <= x <= self._sorted_ranges[idx][1]
            return False
        else:
            # Fallback to original method for custom ranges
            return any(r[0] <= x <= r[1] for r in rl)
    
    def get_imagebase(self):
        """Get image base address"""
        return self.bv.start
    
    def x64_imagebase(self):
        """Get image base for x64 RVA calculations"""
        if self.x64:
            return self.get_imagebase()
        return 0
    
    def get_byte(self, addr):
        """Read a byte from memory"""
        data = self.bv.read(addr, 1)
        return data[0] if data else 0
    
    def get_word(self, addr):
        """Read a 16-bit word from memory"""
        data = self.bv.read(addr, 2)
        if data and len(data) >= 2:
            return struct.unpack('<H', data)[0]
        return 0
    
    def get_dword(self, addr):
        """Read a 32-bit dword from memory"""
        data = self.bv.read(addr, 4)
        if data and len(data) >= 4:
            return struct.unpack('<I', data)[0]
        return 0
    
    def get_signed_dword(self, addr):
        """Read a 32-bit signed dword from memory"""
        data = self.bv.read(addr, 4)
        if data and len(data) >= 4:
            return struct.unpack('<i', data)[0]
        return 0
    
    def get_qword(self, addr):
        """Read a 64-bit qword from memory"""
        data = self.bv.read(addr, 8)
        if data and len(data) >= 8:
            return struct.unpack('<Q', data)[0]
        return 0
    
    def get_ptr(self, addr):
        """Read a pointer-sized value from memory"""
        if self.PTR_SIZE == 8:
            return self.get_qword(addr)
        else:
            return self.get_dword(addr)
    
    def get_strlen(self, addr):
        """Get length of null-terminated string"""
        try:
            data = self.bv.read(addr, 256)  # Read up to 256 bytes
            if not data:
                return None
            
            null_pos = data.find(b'\x00')
            if null_pos == -1:
                return None
            
            return null_pos
        except:
            return None
    
    def get_string(self, addr, max_len=256):
        """Read a null-terminated string from memory"""
        try:
            data = self.bv.read(addr, max_len)
            if not data:
                return None
            
            null_pos = data.find(b'\x00')
            if null_pos == -1:
                return data.decode('utf-8', errors='ignore')
            
            return data[:null_pos].decode('utf-8', errors='ignore')
        except:
            return None
    
    def has_xref(self, addr):
        """Check if address has cross-references"""
        # Binary Ninja returns generators, so check if any exist
        try:
            next(iter(self.bv.get_code_refs(addr)))
            return True
        except StopIteration:
            pass
        
        try:
            next(iter(self.bv.get_data_refs(addr)))
            return True
        except StopIteration:
            pass
        
        return False
    
    def get_xrefs_to(self, addr):
        """Get cross-references to an address"""
        code_refs = list(self.bv.get_code_refs(addr))
        data_refs = list(self.bv.get_data_refs(addr))
        return code_refs + data_refs
    
    def get_name(self, addr):
        """Get symbol name at address"""
        symbol = self.bv.get_symbol_at(addr)
        if symbol:
            return symbol.name
        return None
    
    def set_name(self, addr, name):
        """Set symbol name at address"""
        try:
            self.bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, addr, name))
            return True
        except:
            return False
    
    def is_valid_addr(self, addr):
        """Check if address is valid"""
        return self.bv.is_valid_offset(addr)
    
    def get_func_at(self, addr):
        """Get function at address"""
        return self.bv.get_function_at(addr)
    
    def get_basic_block_at(self, addr):
        """Get basic block containing address"""
        func = self.bv.get_function_at(addr)
        if func:
            for bb in func.basic_blocks:
                if bb.start <= addr < bb.end:
                    return bb
        return None
    
    def find_pattern(self, pattern, start_addr=None, end_addr=None):
        """Find binary pattern in memory"""
        if start_addr is None:
            start_addr = self.bv.start
        if end_addr is None:
            end_addr = self.bv.end
        
        # Convert pattern string to bytes if needed
        if isinstance(pattern, str):
            pattern = bytes.fromhex(pattern.replace(' ', ''))
        
        # Binary Ninja doesn't have a direct pattern search, so we implement a simple one
        search_len = end_addr - start_addr
        if search_len <= 0:
            return []
        
        # Read the entire search range (be careful with large ranges)
        if search_len > 0x100000:  # 1MB limit
            log_warn(f"Pattern search range too large: {search_len:x}")
            return []
        
        data = self.bv.read(start_addr, search_len)
        if not data:
            return []
        
        results = []
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            results.append(start_addr + pos)
            offset = pos + 1
        
        return results
    
    def create_struct_type(self, name, members):
        """Create a structure type"""
        try:
            struct_type = bn.Structure()
            struct_type.packed = True
            
            offset = 0
            for member_name, member_type, member_size in members:
                struct_type.append(bn.StructureMember(member_type, member_name, offset))
                offset += member_size
            
            self.bv.define_user_type(name, struct_type)
            return struct_type
        except:
            return None
    
    def apply_struct_type(self, addr, struct_name):
        """Apply a structure type to memory location"""
        try:
            struct_type = self.bv.get_type_by_name(struct_name)
            if struct_type:
                self.bv.define_user_data_var(addr, struct_type)
                return True
        except:
            pass
        return False
    
    def get_segment_name(self, addr):
        """Get segment/section name containing address"""
        for section_name in self.bv.sections:
            section = self.bv.get_section_by_name(section_name)
            if section and section.start <= addr < section.end:
                return section.name
        return None
    
    def is_executable(self, addr):
        """Check if address is in executable memory"""
        for section_name in self.bv.sections:
            section = self.bv.get_section_by_name(section_name)
            if section and section.start <= addr < section.end:
                return section.semantics == bn.SectionSemantics.ReadOnlyCodeSectionSemantics
        return False
    
    def is_data_section(self, addr):
        """Check if address is in data section"""
        for section_name in self.bv.sections:
            section = self.bv.get_section_by_name(section_name)
            if section and section.start <= addr < section.end:
                return section.semantics in [
                    bn.SectionSemantics.ReadOnlyDataSectionSemantics,
                    bn.SectionSemantics.ReadWriteDataSectionSemantics
                ]
        return False

