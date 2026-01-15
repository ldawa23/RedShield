"""
RedShield Vulnerability Signatures

Custom vulnerability signatures for the built-in detection engine.
This replaces the need for Nuclei by providing our own signature format.
"""

from .loader import SignatureLoader, Signature
from .matcher import SignatureMatcher
from .registry import SignatureRegistry

__all__ = ['SignatureLoader', 'Signature', 'SignatureMatcher', 'SignatureRegistry']
