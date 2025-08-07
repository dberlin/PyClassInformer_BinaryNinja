"""
PyClassInformer tree view for Binary Ninja
Creates a hierarchical class organization view similar to IDA's dirtree functionality
"""

import binaryninja as bn
from binaryninja import log_info, log_warn, log_error
from binaryninja import mainthread
from binaryninja.interaction import show_html_report

class MCTreeBN:
    """Binary Ninja method classifier tree - equivalent to IDA's mc_tree"""
    
    def __init__(self, bv, data, base_class_paths):
        self.bv = bv
        self.data = data
        self.base_class_paths = base_class_paths
        self.class_structure = {}
        
    def process_data(self):
        """Process RTTI data and build class hierarchy structure"""
        for vftable_ea in self.data:
            col = self.data[vftable_ea]
            class_name = col.name
            
            # Initialize class structure
            if class_name not in self.class_structure:
                self.class_structure[class_name] = {
                    'vftables': [],
                    'virtual_methods': [],
                    'constructors_destructors': [],
                    'hierarchy': [],
                    'library_class': getattr(col, 'libflag', False)
                }
            
            bc_path = self.base_class_paths[vftable_ea]
            actual_class_name = class_name
            if bc_path:
                actual_class_name = bc_path[-1].name
            
            # Add vftable information
            vftable_info = {
                'address': vftable_ea,
                'name': self.bv.get_symbol_at(vftable_ea).name if self.bv.get_symbol_at(vftable_ea) else f"vftable_{vftable_ea:x}",
                'offset': col.offset,
                'cd_offset': getattr(col, 'cdOffset', 0),
                'actual_class': actual_class_name
            }
            self.class_structure[class_name]['vftables'].append(vftable_info)
            
            # Add virtual methods
            for vfea in col.vfeas:
                func = self.bv.get_function_at(vfea)
                if func:
                    method_info = {
                        'address': vfea,
                        'name': func.name,
                        'class': actual_class_name
                    }
                    self.class_structure[class_name]['virtual_methods'].append(method_info)
            
            # Add constructor/destructor candidates
            refs = list(self.bv.get_code_refs(vftable_ea)) + list(self.bv.get_data_refs(vftable_ea))
            for ref in refs:
                # Extract address from reference object
                refea = ref.address if hasattr(ref, 'address') else ref
                func = self.bv.get_function_at(refea)
                if func:
                    ctor_dtor_info = {
                        'address': func.start,
                        'name': func.name,
                        'class': actual_class_name
                    }
                    self.class_structure[class_name]['constructors_destructors'].append(ctor_dtor_info)
            
            # Add hierarchy information
            if hasattr(col, 'chd') and hasattr(col.chd, 'bca') and hasattr(col.chd.bca, 'paths'):
                for off in col.chd.bca.paths:
                    for path in col.chd.bca.paths[off]:
                        hierarchy_path = []
                        for bcd in path:
                            hierarchy_info = {
                                'name': bcd.name,
                                'mdisp': bcd.mdisp,
                                'pdisp': bcd.pdisp,
                                'vdisp': bcd.vdisp,
                                'address': getattr(bcd, 'ea', 0)
                            }
                            hierarchy_path.append(hierarchy_info)
                        self.class_structure[class_name]['hierarchy'].append(hierarchy_path)
    
    def generate_html_tree_report(self):
        """Generate comprehensive HTML report with tree-like organization"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>PyClassInformer Class Tree</title>
    <style>
        /* Dark mode as default (direct colors for compatibility) */
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #2b2b2b;
            color: #e8e8e8;
        }
        h1 { color: #5fb85f; }
        h2 { 
            color: #6db3f2; 
            border-bottom: 2px solid #666; 
        }
        h3 { 
            color: #d2b48c; 
            border-bottom: 1px solid #666; 
        }
        h4 { color: #90ee90; }
        .class-container { 
            border: 1px solid #666; 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 5px; 
            background-color: #3a3a3a;
        }
        .library-class { background-color: #5a5a00; }
        .user-class { background-color: #3a4a5a; }
        .section { 
            margin: 10px 0; 
            padding: 10px; 
            background-color: #404040; 
            border-radius: 3px; 
        }
        .address { 
            font-family: monospace; 
            color: #66b3ff; 
            cursor: pointer; 
        }
        .address:hover { background-color: #3a4a5a; }
        .method-list { list-style-type: none; padding-left: 20px; }
        .method-item { 
            margin: 5px 0; 
            padding: 5px; 
            background-color: #383838; 
            border-radius: 3px; 
        }
        .hierarchy-path { 
            margin: 5px 0; 
            padding: 5px; 
            background-color: #384038; 
            border-left: 3px solid #4CAF50; 
        }
        .inheritance-info { 
            font-size: 0.9em; 
            color: #bbb; 
            font-style: italic; 
        }
        .summary { 
            background-color: #3a4a5a; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 10px 0; 
        }
        .collapsible { 
            cursor: pointer; 
            padding: 10px; 
            background-color: #4a4a4a; 
            border: none; 
            width: 100%; 
            text-align: left;
            color: #e8e8e8;
        }
        .collapsible:hover { background-color: #5a5a5a; }
        .content { 
            display: none; 
            padding: 10px; 
            border: 1px solid #666; 
            background-color: #353535;
        }
        .vftable-info { 
            background-color: #5a3a3a; 
            padding: 5px; 
            margin: 5px 0; 
            border-radius: 3px; 
        }
        
        /* Light mode with softer backgrounds */
        @media (prefers-color-scheme: light) {
            body { 
                background-color: #f8f8f8;
                color: #000000;
            }
            h1 { color: #2E8B57; }
            h2 { 
                color: #4682B4; 
                border-bottom: 2px solid #ccc; 
            }
            h3 { 
                color: #8B4513; 
                border-bottom: 1px solid #ccc; 
            }
            h4 { color: #2F4F4F; }
            .class-container { 
                border: 1px solid #ccc; 
                background-color: #fafafa;
            }
            .library-class { background-color: #fff8e1; }
            .user-class { background-color: #f0f8ff; }
            .section { 
                background-color: #f5f5f5; 
            }
            .address { 
                color: #0066cc; 
            }
            .address:hover { background-color: #e6f3ff; }
            .method-item { 
                background-color: #f9f9f9; 
            }
            .hierarchy-path { 
                background-color: #f0fff0; 
                border-left: 3px solid #4CAF50; 
            }
            .inheritance-info { 
                color: #666; 
            }
            .summary { 
                background-color: #f0f8ff; 
            }
            .collapsible { 
                background-color: #f0f0f0; 
                color: #000000;
            }
            .collapsible:hover { background-color: #e8e8e8; }
            .content { 
                border: 1px solid #ccc; 
                background-color: #fafafa;
            }
            .vftable-info { 
                background-color: #fff5f5; 
            }
        }
    </style>
    <script>
        function toggleSection(element) {
            var content = element.nextElementSibling;
            if (content.style.display === "block") {
                content.style.display = "none";
                element.innerHTML = element.innerHTML.replace("▼", "▶");
            } else {
                content.style.display = "block";
                element.innerHTML = element.innerHTML.replace("▶", "▼");
            }
        }
        
        function jumpToAddress(addr) {
            // In a real Binary Ninja plugin, this would trigger navigation
            console.log("Navigate to address: " + addr);
        }
    </script>
</head>
<body>
    <h1>🏗️ PyClassInformer Class Tree Structure</h1>
"""
        
        if not self.class_structure:
            html += "<p>No class structures found.</p></body></html>"
            return html
        
        # Summary section
        total_classes = len(self.class_structure)
        library_classes = sum(1 for cls_data in self.class_structure.values() if cls_data['library_class'])
        total_methods = sum(len(cls_data['virtual_methods']) for cls_data in self.class_structure.values())
        total_ctors_dtors = sum(len(cls_data['constructors_destructors']) for cls_data in self.class_structure.values())
        
        html += f"""
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Classes:</strong> {total_classes}</p>
        <p><strong>Library Classes:</strong> {library_classes}</p>
        <p><strong>User Classes:</strong> {total_classes - library_classes}</p>
        <p><strong>Total Virtual Methods:</strong> {total_methods}</p>
        <p><strong>Total Constructors/Destructors:</strong> {total_ctors_dtors}</p>
    </div>
"""
        
        # Process each class
        for class_name, class_data in sorted(self.class_structure.items()):
            class_type = "library-class" if class_data['library_class'] else "user-class"
            class_icon = "📚" if class_data['library_class'] else "👤"
            
            html += f"""
    <div class="class-container {class_type}">
        <h2>{class_icon} {class_name}</h2>
"""
            
            # VFTables section
            if class_data['vftables']:
                html += f"""
        <button class="collapsible" onclick="toggleSection(this)">▼ VFTables ({len(class_data['vftables'])})</button>
        <div class="content" style="display: block;">
"""
                for vftable in class_data['vftables']:
                    html += f"""
            <div class="vftable-info">
                <strong>📋 {vftable['name']}</strong><br>
                <span class="address" onclick="jumpToAddress('0x{vftable['address']:x}')">Address: 0x{vftable['address']:x}</span><br>
                Offset: 0x{vftable['offset']:x} | CD Offset: 0x{vftable['cd_offset']:x}<br>
                Actual Class: {vftable['actual_class']}
            </div>
"""
                html += "        </div>\n"
            
            # Virtual Methods section
            if class_data['virtual_methods']:
                html += f"""
        <button class="collapsible" onclick="toggleSection(this)">▼ Virtual Methods ({len(class_data['virtual_methods'])})</button>
        <div class="content" style="display: block;">
            <ul class="method-list">
"""
                for method in class_data['virtual_methods']:
                    html += f"""
                <li class="method-item">
                    🔧 <strong>{method['name']}</strong><br>
                    <span class="address" onclick="jumpToAddress('0x{method['address']:x}')">0x{method['address']:x}</span>
                    <span class="inheritance-info">in {method['class']}</span>
                </li>
"""
                html += "            </ul>\n        </div>\n"
            
            # Constructors/Destructors section
            if class_data['constructors_destructors']:
                html += f"""
        <button class="collapsible" onclick="toggleSection(this)">▼ Possible Constructors/Destructors ({len(class_data['constructors_destructors'])})</button>
        <div class="content" style="display: block;">
            <ul class="method-list">
"""
                for ctor_dtor in class_data['constructors_destructors']:
                    html += f"""
                <li class="method-item">
                    🏗️ <strong>{ctor_dtor['name']}</strong><br>
                    <span class="address" onclick="jumpToAddress('0x{ctor_dtor['address']:x}')">0x{ctor_dtor['address']:x}</span>
                    <span class="inheritance-info">for {ctor_dtor['class']}</span>
                </li>
"""
                html += "            </ul>\n        </div>\n"
            
            # Hierarchy section
            if class_data['hierarchy']:
                html += f"""
        <button class="collapsible" onclick="toggleSection(this)">▼ Inheritance Hierarchy ({len(class_data['hierarchy'])} paths)</button>
        <div class="content" style="display: block;">
"""
                for i, hierarchy_path in enumerate(class_data['hierarchy']):
                    html += f"            <div class=\"hierarchy-path\">\n                <strong>🌳 Inheritance Path {i+1}:</strong><br>\n"
                    for j, bcd in enumerate(hierarchy_path):
                        indent = "  " * j
                        html += f"                {indent}📁 {bcd['name']} (mdisp: {bcd['mdisp']}, pdisp: {bcd['pdisp']}, vdisp: {bcd['vdisp']})<br>\n"
                    html += "            </div>\n"
                html += "        </div>\n"
            
            html += "    </div>\n"
        
        html += """
    <h2>📖 Legend</h2>
    <ul>
        <li><strong>📚 Library Classes:</strong> Classes from standard libraries (STL, MFC, etc.)</li>
        <li><strong>👤 User Classes:</strong> Classes defined in the target application</li>
        <li><strong>📋 VFTables:</strong> Virtual function table structures</li>
        <li><strong>🔧 Virtual Methods:</strong> Virtual member functions</li>
        <li><strong>🏗️ Constructors/Destructors:</strong> Functions that reference VFTables</li>
        <li><strong>🌳 Inheritance Hierarchy:</strong> Base class relationships</li>
        <li><strong>mdisp:</strong> Member displacement</li>
        <li><strong>pdisp:</strong> Parent displacement</li>
        <li><strong>vdisp:</strong> Virtual displacement</li>
    </ul>
</body>
</html>
"""
        return html
    
    def apply_symbol_grouping_tags(self):
        """Apply comprehensive tagging to organize symbols by type"""
        for class_name, class_data in self.class_structure.items():
            class_type = "LibraryClass" if class_data['library_class'] else "UserClass"
            
            # Tag VFTables
            for vftable in class_data['vftables']:
                try:
                    self.bv.add_tag(vftable['address'], "VFTable", f"Virtual function table for {class_name}")
                    self.bv.add_tag(vftable['address'], class_type, class_name)
                except Exception as e:
                    log_warn(f"Failed to tag VFTable at 0x{vftable['address']:x}: {e}")
            
            # Tag virtual methods
            for method in class_data['virtual_methods']:
                func = self.bv.get_function_at(method['address'])
                if func:
                    try:
                        func.add_tag("VirtualMethod", f"Virtual method of {class_name}")
                        func.add_tag(class_type, class_name)
                        self.bv.add_tag(method['address'], "VirtualMethod", f"Virtual method of {class_name}")
                        self.bv.add_tag(method['address'], class_type, class_name)
                    except Exception as e:
                        log_warn(f"Failed to tag virtual method at 0x{method['address']:x}: {e}")
            
            # Tag constructors/destructors
            for ctor_dtor in class_data['constructors_destructors']:
                func = self.bv.get_function_at(ctor_dtor['address'])
                if func:
                    try:
                        func.add_tag("Constructor/Destructor", f"Possible ctor/dtor of {class_name}")
                        func.add_tag(class_type, class_name)
                        self.bv.add_tag(ctor_dtor['address'], "Constructor/Destructor", f"Possible ctor/dtor of {class_name}")
                        self.bv.add_tag(ctor_dtor['address'], class_type, class_name)
                    except Exception as e:
                        log_warn(f"Failed to tag ctor/dtor at 0x{ctor_dtor['address']:x}: {e}")
        
        log_info(f"Applied symbol grouping tags to {len(self.class_structure)} classes")

def show_mc_tree_bn(bv, data, base_class_paths):
    """Show method classifier tree for Binary Ninja - equivalent to IDA's show_mc_tree_t"""
    def display_tree():
        """Display function that runs on main thread"""
        if not data:
            log_info("No RTTI data to display in tree view")
            return None
        
        # Create tree and process data
        tree = MCTreeBN(bv, data, base_class_paths)
        tree.process_data()
        
        # Apply symbol grouping tags
        tree.apply_symbol_grouping_tags()
        
        # Generate and show HTML report
        html_content = tree.generate_html_tree_report()
        show_html_report("PyClassInformer Class Tree", html_content)
        
        # Log summary
        log_info(f"PyClassInformer Class Tree: {len(tree.class_structure)} classes organized")
        log_info("Class tree displayed in HTML report window")
        log_info("Symbol grouping tags applied - use Binary Ninja's tag filters to navigate")
        
        return tree
    
    # Ensure this runs on the main thread for UI operations
    if mainthread.is_main_thread():
        return display_tree()
    else:
        return mainthread.execute_on_main_thread(display_tree)