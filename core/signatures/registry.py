"""
RedShield Signature Registry

Central registry for managing vulnerability signatures.
Provides search, filtering, and management capabilities.
"""

from typing import List, Dict, Optional, Set
from .loader import SignatureLoader, Signature, Severity


class SignatureRegistry:
    """
    Central registry for vulnerability signatures.
    
    Provides:
    - Signature loading and management
    - Search and filtering
    - Statistics and reporting
    - Custom signature registration
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._loader = SignatureLoader()
        self._custom_signatures: Dict[str, Signature] = {}
        self._disabled_ids: Set[str] = set()
        self._initialized = True
    
    @property
    def signatures(self) -> List[Signature]:
        """Get all enabled signatures."""
        all_sigs = list(self._loader.signatures.values()) + list(self._custom_signatures.values())
        return [s for s in all_sigs if s.id not in self._disabled_ids and s.enabled]
    
    @property
    def all_signatures(self) -> List[Signature]:
        """Get all signatures including disabled ones."""
        return list(self._loader.signatures.values()) + list(self._custom_signatures.values())
    
    def load_custom_signatures(self, directory: str) -> int:
        """Load custom signatures from a directory."""
        loaded = self._loader.load_directory(directory)
        return len(loaded)
    
    def register_signature(self, signature: Signature) -> bool:
        """Register a custom signature."""
        if signature.id in self._loader.signatures or signature.id in self._custom_signatures:
            return False
        self._custom_signatures[signature.id] = signature
        return True
    
    def unregister_signature(self, signature_id: str) -> bool:
        """Unregister a custom signature."""
        if signature_id in self._custom_signatures:
            del self._custom_signatures[signature_id]
            return True
        return False
    
    def enable_signature(self, signature_id: str) -> bool:
        """Enable a disabled signature."""
        self._disabled_ids.discard(signature_id)
        return True
    
    def disable_signature(self, signature_id: str) -> bool:
        """Disable a signature."""
        self._disabled_ids.add(signature_id)
        return True
    
    def get_signature(self, signature_id: str) -> Optional[Signature]:
        """Get a signature by ID."""
        if signature_id in self._loader.signatures:
            return self._loader.signatures[signature_id]
        return self._custom_signatures.get(signature_id)
    
    def search(self, query: str) -> List[Signature]:
        """Search signatures by name, description, or tags."""
        return self._loader.search(query)
    
    def filter_by_severity(self, severity: Severity) -> List[Signature]:
        """Filter signatures by severity."""
        return [s for s in self.signatures if s.severity == severity]
    
    def filter_by_category(self, category: str) -> List[Signature]:
        """Filter signatures by OWASP category."""
        return [s for s in self.signatures if category.lower() in s.category.lower()]
    
    def filter_by_tag(self, tag: str) -> List[Signature]:
        """Filter signatures by tag."""
        return [s for s in self.signatures if tag.lower() in [t.lower() for t in s.tags]]
    
    def get_statistics(self) -> Dict[str, any]:
        """Get signature statistics."""
        sigs = self.signatures
        
        by_severity = {}
        for sev in Severity:
            by_severity[sev.value] = len([s for s in sigs if s.severity == sev])
        
        categories = set()
        tags = set()
        for sig in sigs:
            categories.add(sig.category)
            tags.update(sig.tags)
        
        return {
            'total': len(sigs),
            'builtin': len(self._loader.signatures),
            'custom': len(self._custom_signatures),
            'disabled': len(self._disabled_ids),
            'by_severity': by_severity,
            'categories': list(categories),
            'tags': list(tags)
        }
    
    def export_signatures(self, signature_ids: List[str] = None) -> List[Dict]:
        """Export signatures to dictionary format."""
        if signature_ids:
            sigs = [self.get_signature(sid) for sid in signature_ids if self.get_signature(sid)]
        else:
            sigs = self.signatures
        
        return [s.to_dict() for s in sigs]
    
    def get_mitre_mapping(self) -> Dict[str, List[Signature]]:
        """Get signatures grouped by MITRE ATT&CK technique."""
        mapping = {}
        for sig in self.signatures:
            if sig.mitre_attack:
                if sig.mitre_attack not in mapping:
                    mapping[sig.mitre_attack] = []
                mapping[sig.mitre_attack].append(sig)
        return mapping
    
    def get_owasp_mapping(self) -> Dict[str, List[Signature]]:
        """Get signatures grouped by OWASP category."""
        mapping = {}
        for sig in self.signatures:
            if sig.category not in mapping:
                mapping[sig.category] = []
            mapping[sig.category].append(sig)
        return mapping


# Global registry instance
registry = SignatureRegistry()
