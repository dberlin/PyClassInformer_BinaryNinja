"""
PyClassInformer for Binary Ninja
Main module for RTTI parsing and analysis
"""

import binaryninja as bn
from binaryninja import log_info, log_warn, log_error
from binaryninja import mainthread

from . import msvc_rtti_bn
from . import pci_config
from . import pci_config_form_bn
from . import pci_chooser_bn
from . import method_classifier_bn
from . import lib_classes_checker_bn

def run_pci(bv, config=None, progress_callback=None):
    """Main entry point for PyClassInformer analysis (runs on worker thread)"""
    def analysis_worker():
        """Worker function that performs the actual analysis"""
        def update_progress(message, percent=None):
            """Update progress on main thread"""
            mainthread.execute_on_main_thread(lambda: log_info(message))
            if progress_callback:
                mainthread.execute_on_main_thread(lambda: progress_callback(message, percent))
        
        update_progress("Starting PyClassInformer for Binary Ninja", 0)
        
        if config is None:
            analysis_config = pci_config.pci_config()
        else:
            analysis_config = config
        
        # Check if binary is suitable for RTTI analysis
        update_progress("Checking binary compatibility...", 10)
        if not _is_suitable_binary(bv):
            update_progress("Binary may not contain MSVC RTTI structures", 100)
            mainthread.execute_on_main_thread(lambda: log_warn("Binary may not contain MSVC RTTI structures"))
            return None
        
        # Find vftables with relevant RTTI structures
        update_progress("Analyzing RTTI structures...", 20)
        result = msvc_rtti_bn.rtti_parser.run(bv, alldata=analysis_config.alldata)
        
        # Show results on main thread
        tree = None
        if result:
            update_progress(f"Found {len(result)} classes with RTTI information", 60)
            
            if analysis_config.rtti:
                update_progress("Displaying RTTI results...", 70)
                mainthread.execute_on_main_thread(lambda: msvc_rtti_bn.rtti_parser.show(result))
            
            # Apply library flags to known classes
            update_progress("Classifying library classes...", 80)
            lib_classes_checker_bn.set_libflag(bv, result)
            
            # Show main chooser interface on main thread
            update_progress("Generating results report...", 90)
            pci_chooser_bn.show_pci_chooser_t(bv, result)
            
            # Create method classifier tree if supported
            if analysis_config.exana:
                update_progress("Creating method classifier...", 95)
                tree = method_classifier_bn.method_classifier(bv, result, config=analysis_config)
            
        else:
            update_progress("No RTTI structures found", 100)
            mainthread.execute_on_main_thread(lambda: log_warn("No RTTI structures found. Binary might not be a Windows C++ program or RTTI might be disabled."))
        
        update_progress("PyClassInformer analysis complete", 100)
        return tree
    
    # Enqueue analysis on Binary Ninja's worker thread system
    mainthread.worker_enqueue(analysis_worker, "PyClassInformer Analysis")
    
    return None  # Actual result will be shown via UI callbacks

def run_pci_with_config(bv):
    """Run PyClassInformer with configuration dialog"""
    def config_and_run():
        """Show config dialog on main thread, then run analysis on worker thread"""
        log_info("Starting PyClassInformer with configuration...")
        
        # Show configuration form (must be on main thread for UI)
        config = pci_config_form_bn.show_simple_config_form()
        if config is None:
            log_info("PyClassInformer cancelled by user")
            return None
        
        # Define progress callback for user feedback
        def progress_callback(message, percent):
            """Callback to show progress to user"""
            if percent is not None:
                log_info(f"[{percent:3d}%] {message}")
            else:
                log_info(message)
        
        # Run analysis with chosen configuration (will spawn its own worker thread)
        return run_pci(bv, config, progress_callback)
    
    # Execute configuration on main thread
    return mainthread.execute_on_main_thread(config_and_run)

def run_pci_simple(bv):
    """Run PyClassInformer with default settings (for quick access)"""
    def progress_callback(message, percent):
        """Simple progress callback"""
        if percent is not None:
            log_info(f"[{percent:3d}%] {message}")
        else:
            log_info(message)
    
    return run_pci(bv, None, progress_callback)

def _is_suitable_binary(bv):
    """Check if binary is suitable for RTTI analysis"""
    # Check if it's a PE file
    if bv.platform.name not in ['windows-x86', 'windows-x86_64', 'windows-armv7', 'windows-aarch64']:
        return False
    
    # Check for basic PE structure
    if not hasattr(bv, 'get_section_by_name'):
        return False
        
    # Look for typical RTTI sections
    rtti_sections = ['.rdata', '.data', '.text']
    has_rtti_section = any(bv.get_section_by_name(name) for name in rtti_sections)
    
    return has_rtti_section

def main():
    """Standalone main function for testing"""
    pass

if __name__ == '__main__':
    main()