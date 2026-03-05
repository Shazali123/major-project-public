"""
Module Manager - Dynamically discovers and executes test modules
"""

import os
import importlib.util
import sys
from typing import List, Dict
from system_monitor import SystemMonitor


class ModuleManager:
    """Manages discovery and execution of test modules"""
    
    def __init__(self, modules_dir: str = "modules"):
        """
        Initialize module manager
        
        Args:
            modules_dir: Directory containing module folders
        """
        self.modules_dir = modules_dir
        self.modules: List = []
        self.results: List[Dict] = []
        
    def discover_modules(self):
        """
        Dynamically discover all modules in the modules directory
        Modules must be in folders matching pattern: module_*
        """
        self.modules = []
        
        if not os.path.exists(self.modules_dir):
            print(f"[ModuleManager] Modules directory not found: {self.modules_dir}")
            return
            
        # Get all module folders
        module_folders = []
        for item in os.listdir(self.modules_dir):
            item_path = os.path.join(self.modules_dir, item)
            if os.path.isdir(item_path) and item.startswith('module_'):
                module_folders.append(item)
                
        # Sort folders to determine execution order
        module_folders.sort()
        
        print(f"[ModuleManager] Found {len(module_folders)} module(s)")
        
        # Load each module
        for idx, folder in enumerate(module_folders, start=1):
            try:
                module_path = os.path.join(self.modules_dir, folder, 'module.py')
                
                if not os.path.exists(module_path):
                    print(f"[ModuleManager] Warning: {folder}/module.py not found, skipping")
                    continue
                    
                # Load module dynamically
                spec = importlib.util.spec_from_file_location(f"{folder}.module", module_path)
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"{folder}.module"] = module
                spec.loader.exec_module(module)
                
                # Find the module class (should inherit from BaseModule)
                module_class = None
                for name in dir(module):
                    obj = getattr(module, name)
                    if isinstance(obj, type) and name.endswith('Module') and name != 'BaseModule':
                        module_class = obj
                        break
                        
                if module_class:
                    # Instantiate module and assign ID
                    module_instance = module_class()
                    module_instance.set_module_id(idx)
                    self.modules.append(module_instance)
                    print(f"[ModuleManager] Loaded: {folder} (ID: {idx})")
                else:
                    print(f"[ModuleManager] Warning: No module class found in {folder}")
                    
            except Exception as e:
                print(f"[ModuleManager] Error loading {folder}: {e}")
                
        print(f"[ModuleManager] Successfully loaded {len(self.modules)} module(s)")
        
    def run_modules(self, progress_callback=None) -> List[Dict]:
        """
        Execute all modules sequentially
        
        Args:
            progress_callback: Optional callback function(current, total, module_name)
            
        Returns:
            List of module results
        """
        self.results = []
        total_modules = len(self.modules)
        
        print(f"\n[ModuleManager] Starting execution of {total_modules} modules...")
        print("=" * 60)
        
        for idx, module in enumerate(self.modules, start=1):
            module_info = module.get_info()
            print(f"\n[{idx}/{total_modules}] Running: {module_info['name']}")
            
            if progress_callback:
                progress_callback(idx, total_modules, module_info['name'])
                
            # Create monitor for this module
            monitor = SystemMonitor()
            
            # Run module
            success = module.run(monitor)
            
            # Get results
            results = module.get_results()
            self.results.append(results)
            
            status = "✓" if success else "✗"
            print(f"[{idx}/{total_modules}] {status} {module_info['name']}: {results['status']}")
            
        print("=" * 60)
        print(f"[ModuleManager] All modules completed\n")
        
        return self.results
        
    def get_module_count(self) -> int:
        """Get number of discovered modules"""
        return len(self.modules)
        
    def get_module_list(self) -> List[Dict]:
        """Get list of module information"""
        return [m.get_info() for m in self.modules]
