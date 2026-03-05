"""
Base Module - Abstract base class for all test modules
"""

from abc import ABC, abstractmethod
from typing import Dict
from system_monitor import SystemMonitor


class BaseModule(ABC):
    """Base class that all test modules must inherit from"""
    
    def __init__(self):
        self.module_id: int = None
        self.name: str = "Unknown Module"
        self.description: str = ""
        self.execution_time: float = 0
        self.status: str = "Pending"
        self.metrics: Dict = {}
        
    @abstractmethod
    def get_info(self) -> Dict:
        """
        Get module metadata
        
        Returns:
            Dictionary with module information (id, name, description)
        """
        pass
        
    @abstractmethod
    def run(self, monitor: SystemMonitor) -> bool:
        """
        Execute the module's test logic
        
        Args:
            monitor: SystemMonitor instance for tracking metrics
            
        Returns:
            True if successful, False otherwise
        """
        pass
        
    @abstractmethod
    def get_results(self) -> Dict:
        """
        Get module execution results
        
        Returns:
            Dictionary containing execution results and metrics
        """
        pass
        
    def set_module_id(self, module_id: int):
        """Set the unique module ID"""
        self.module_id = module_id
