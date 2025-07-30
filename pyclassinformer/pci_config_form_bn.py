"""
PyClassInformer Configuration Form for Binary Ninja
UI form for configuring analysis options
"""

import binaryninja as bn
from binaryninja import log_info, log_warn, log_error
from binaryninja.interaction import get_choice_input, get_text_line_input, show_message_box, MessageBoxButtonSet, MessageBoxIcon
from . import pci_config

class PCIConfigFormBN:
    """Binary Ninja configuration form for PyClassInformer"""
    
    def __init__(self):
        self.config = None
        self.cancelled = False
    
    def show_config_dialog(self):
        """Show configuration dialog and return config object"""
        # Create default config
        default_config = pci_config.pci_config()
        
        # Get search area preference
        search_choices = [
            "Only .rdata section",
            "All data sections"
        ]
        
        search_choice = get_choice_input(
            "PyClassInformer - Search Area",
            "Select which sections to search for RTTI information:",
            search_choices
        )
        
        if search_choice is None:
            self.cancelled = True
            return None
        
        alldata = (search_choice == 1)  # 0 = .rdata only, 1 = all data
        
        # Get analysis options
        options_text = """Select analysis options (enter comma-separated numbers):

1. Display RTTI parsed results in the log
2. Display extra analysis results (class tree view + comprehensive tagging)
3. Apply comprehensive symbol grouping tags for virtual methods
4. Apply comprehensive symbol grouping tags for constructors/destructors  
5. Rename virtual methods with class prefixes
6. Rename possible constructors and destructors

Example: 1,2,5,6 (or just press Enter for all options)
Note: Option 2 enables the interactive class tree view like IDA's dirtree organization"""
        
        user_input = get_text_line_input(
            options_text,
            "Options"
        )
        
        if user_input is None:
            self.cancelled = True
            return None
        
        # Decode bytes to string if necessary
        if isinstance(user_input, bytes):
            user_input = user_input.decode('utf-8')
        
        # Parse user input or use defaults
        if user_input.strip() == "":
            # Default: all options enabled
            selected_options = [1, 2, 3, 4, 5, 6]
        else:
            try:
                selected_options = [int(x.strip()) for x in user_input.split(',') if x.strip().isdigit()]
            except ValueError:
                show_message_box(
                    "Invalid Input", 
                    "Please enter comma-separated numbers (1-6) or leave empty for all options.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon
                )
                return self.show_config_dialog()  # Retry
        
        # Map options to config parameters
        rtti = 1 in selected_options
        exana = 2 in selected_options
        mvvm = 3 in selected_options
        mvcd = 4 in selected_options
        rnvm = 5 in selected_options  
        rncd = 6 in selected_options
        
        # Create and return config
        self.config = pci_config.pci_config(
            alldata=alldata,
            rtti=rtti,
            exana=exana,
            mvvm=mvvm,
            mvcd=mvcd,
            rnvm=rnvm,
            rncd=rncd
        )
        
        # Show confirmation
        settings_summary = f"""PyClassInformer Configuration:

Search Area: {'All data sections' if alldata else 'Only .rdata section'}

Analysis Options:
{'✓' if rtti else '✗'} Display RTTI parsed results
{'✓' if exana else '✗'} Display class tree view + comprehensive tagging
{'✓' if mvvm else '✗'} Apply symbol grouping tags for virtual methods
{'✓' if mvcd else '✗'} Apply symbol grouping tags for constructors/destructors
{'✓' if rnvm else '✗'} Rename virtual methods with class prefixes
{'✓' if rncd else '✗'} Rename constructors and destructors

Proceed with analysis?"""
        
        proceed = show_message_box(
            "Confirm Configuration",
            settings_summary,
            MessageBoxButtonSet.YesNoButtonSet,
            MessageBoxIcon.QuestionIcon
        )
        
        if proceed == 1:  # Yes
            return self.config
        else:
            self.cancelled = True
            return None

def show_config_form():
    """Show PyClassInformer configuration form and return config"""
    form = PCIConfigFormBN()
    return form.show_config_dialog()

def show_simple_config_form():
    """Simplified configuration form with fewer options"""
    choices = [
        "Quick Analysis (RTTI display + renaming)",
        "Full Analysis (tree view + all options enabled)",
        "Custom Configuration"
    ]
    
    choice = get_choice_input(
        "PyClassInformer",
        "Select analysis mode:",
        choices
    )
    
    if choice is None:
        return None
    
    if choice == 0:  # Quick Analysis
        return pci_config.pci_config(
            alldata=False,  # .rdata only
            rtti=True,
            exana=False,
            mvvm=False,
            mvcd=False,
            rnvm=True,
            rncd=True
        )
    elif choice == 1:  # Full Analysis
        return pci_config.pci_config(
            alldata=True,   # All sections
            rtti=True,
            exana=True,
            mvvm=True,
            mvcd=True,
            rnvm=True,
            rncd=True
        )
    else:  # Custom Configuration
        return show_config_form()