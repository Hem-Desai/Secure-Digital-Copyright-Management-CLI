from abc import ABC, abstractmethod
from typing import Any, List, Optional

class StorageInterface(ABC):
    """Abstract base class defining storage operations"""
    
    @abstractmethod
    def create(self, data: Any) -> str:
        """Create a new record"""
        pass
    
    @abstractmethod
    def read(self, id: str) -> Optional[Any]:
        """Read a record by ID"""
        pass
    
    @abstractmethod
    def update(self, id: str, data: Any) -> bool:
        """Update a record"""
        pass
    
    @abstractmethod
    def delete(self, id: str) -> bool:
        """Delete a record"""
        pass
    
    @abstractmethod
    def list(self) -> List[Any]:
        """List all records"""
        pass 