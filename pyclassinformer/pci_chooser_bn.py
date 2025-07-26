"""
PyClassInformer chooser for Binary Ninja
UI component for displaying RTTI analysis results
"""

import binaryninja as bn
from binaryninja import log_info, log_warn, log_error
from binaryninja import mainthread
from binaryninja.interaction import show_html_report

class PCIChooserBN:
    """Binary Ninja UI component for displaying RTTI results"""
    
    def __init__(self, bv, data):
        self.bv = bv
        self.data = data
        
    def generate_html_report(self):
        """Generate HTML report of RTTI analysis results"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>PyClassInformer Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2E8B57; }
        h2 { color: #4682B4; border-bottom: 1px solid #ccc; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .vftable { font-family: monospace; color: #0066cc; }
        .classname { font-weight: bold; color: #cc6600; }
        .hierarchy { font-style: italic; color: #666; }
        .libflag { background-color: #fff2cc; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .summary { background-color: #e6f3ff; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>PyClassInformer RTTI Analysis Results</h1>
"""
        
        if not self.data:
            html += "<p>No RTTI structures found in the binary.</p></body></html>"
            return html
        
        # Summary section
        total_classes = len(self.data)
        lib_classes = sum(1 for item in self.data.values() if hasattr(item, 'libflag') and item.libflag)
        
        html += f"""
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Classes Found:</strong> {total_classes}</p>
        <p><strong>Library Classes:</strong> {lib_classes}</p>
        <p><strong>User Classes:</strong> {total_classes - lib_classes}</p>
    </div>
"""
        
        # Results table
        html += """
    <h2>Class Details</h2>
    <table>
        <thead>
            <tr>
                <th>Vftable Address</th>
                <th>Methods</th>
                <th>Flags</th>
                <th>Type</th>
                <th>Hierarchy</th>
                <th>Offset</th>
                <th>Library</th>
            </tr>
        </thead>
        <tbody>
"""
        
        # Sort by address for consistent display
        sorted_items = sorted(self.data.items(), key=lambda x: x[0])
        
        for vftable_ea, col_data in sorted_items:
            methods_count = len(getattr(col_data, 'vfeas', []))
            flags = getattr(col_data, 'flags', 'N/A')
            if hasattr(col_data, 'chd') and hasattr(col_data.chd, 'flags'):
                flags = col_data.chd.flags
            
            class_name = getattr(col_data, 'name', 'Unknown')
            offset = getattr(col_data, 'offset', 0)
            is_lib = getattr(col_data, 'libflag', False)
            
            # Generate hierarchy info
            hierarchy = self._get_hierarchy(col_data)
            
            lib_class = "libflag" if is_lib else ""
            
            html += f"""
            <tr class="{lib_class}">
                <td class="vftable">0x{vftable_ea:x}</td>
                <td>{methods_count}</td>
                <td>{flags}</td>
                <td class="classname">{class_name}</td>
                <td class="hierarchy">{hierarchy}</td>
                <td>0x{offset:x}</td>
                <td>{'Yes' if is_lib else 'No'}</td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
    
    <h2>Legend</h2>
    <ul>
        <li><strong>Vftable Address:</strong> Virtual function table address</li>
        <li><strong>Methods:</strong> Number of virtual methods in the class</li>
        <li><strong>Flags:</strong> RTTI flags and characteristics</li>
        <li><strong>Type:</strong> Class name from RTTI information</li>
        <li><strong>Hierarchy:</strong> Inheritance relationships</li>
        <li><strong>Offset:</strong> Virtual table offset within the class</li>
        <li><strong>Library:</strong> Whether this appears to be a library class</li>
        <li><span style="background-color: #fff2cc; padding: 2px;">Highlighted rows</span> indicate library classes</li>
    </ul>
    
</body>
</html>
"""
        return html
    
    def _get_hierarchy(self, col_data):
        """Extract hierarchy information from COL data"""
        if not hasattr(col_data, 'chd'):
            return "No hierarchy info"
        
        try:
            # Try to get base class information
            if hasattr(col_data.chd, 'bca') and hasattr(col_data.chd.bca, 'bases'):
                bases = col_data.chd.bca.bases
                if bases:
                    base_names = []
                    for base in bases:
                        if hasattr(base, 'name'):
                            base_names.append(base.name)
                    if base_names:
                        return f"{col_data.name}: " + ", ".join(base_names)
            
            return f"{col_data.name}: (base class)"
        except:
            return getattr(col_data, 'name', 'Unknown')

def show_pci_chooser_t(bv, results):
    """Show RTTI analysis results in Binary Ninja UI (thread-safe)"""
    def display_results():
        """Display function that runs on main thread"""
        if not results:
            log_info("No RTTI results to display")
            return
        
        # Create chooser and generate report
        chooser = PCIChooserBN(bv, results)
        html_content = chooser.generate_html_report()
        
        # Show HTML report in Binary Ninja
        show_html_report("PyClassInformer Results", html_content)
        
        # Also log summary to console
        log_info(f"PyClassInformer found {len(results)} classes with RTTI information")
        log_info("Detailed results displayed in HTML report window")
    
    # Ensure this runs on the main thread for UI operations
    if mainthread.is_main_thread():
        display_results()
    else:
        mainthread.execute_on_main_thread(display_results)