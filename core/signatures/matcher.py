"""
RedShield Signature Matcher

The detection engine that matches signatures against scan results.
This replaces Nuclei with our own custom detection engine.
"""

import re
import socket
import ssl
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from .loader import Signature, DetectionType, Severity


@dataclass
class MatchResult:
    """Result of a signature match attempt."""
    signature: Signature
    matched: bool
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    target: str = ""
    port: int = 0
    service: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_vulnerability(self) -> Dict[str, Any]:
        """Convert to vulnerability dictionary format."""
        return {
            'signature_id': self.signature.id,
            'type': self.signature.name,
            'vuln_type': self.signature.id.replace('RS-', '').replace('-', '_'),
            'severity': self.signature.severity.value,
            'description': self.signature.description,
            'target': self.target,
            'port': self.port,
            'service': self.service,
            'category': self.signature.category,
            'mitre_attack': self.signature.mitre_attack,
            'cve_ids': self.signature.cve_ids,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'remediation': {
                'description': self.signature.remediation.description,
                'playbook': self.signature.remediation.playbook,
                'steps': self.signature.remediation.manual_steps
            } if self.signature.remediation else None
        }


class SignatureMatcher:
    """
    The core detection engine.
    
    Matches vulnerability signatures against targets to find security issues.
    
    Usage:
        matcher = SignatureMatcher(signatures)
        results = matcher.scan(target="192.168.1.100", ports=[80, 443, 22])
    """
    
    def __init__(self, signatures: List[Signature], timeout: int = 5, threads: int = 10):
        self.signatures = signatures
        self.timeout = timeout
        self.threads = threads
        self._banner_cache = {}
    
    def scan(self, target: str, ports: List[int], services: Dict[int, str] = None) -> List[MatchResult]:
        """
        Scan a target against all signatures.
        
        Args:
            target: IP address or hostname
            ports: List of open ports to check
            services: Optional mapping of port -> service name
            
        Returns:
            List of MatchResults for vulnerabilities found
        """
        results = []
        services = services or {}
        
        # Collect banners for open ports
        banners = self._collect_banners(target, ports)
        
        # Match each signature
        for signature in self.signatures:
            if not signature.enabled:
                continue
            
            match_result = self._match_signature(target, ports, services, banners, signature)
            if match_result and match_result.matched:
                results.append(match_result)
        
        return results
    
    def scan_parallel(self, target: str, ports: List[int], services: Dict[int, str] = None) -> List[MatchResult]:
        """Parallel version of scan using thread pool."""
        results = []
        services = services or {}
        banners = self._collect_banners(target, ports)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._match_signature, target, ports, services, banners, sig): sig
                for sig in self.signatures if sig.enabled
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result.matched:
                        results.append(result)
                except Exception as e:
                    pass  # Skip failed matches
        
        return results
    
    def _match_signature(self, target: str, ports: List[int], services: Dict[int, str],
                         banners: Dict[int, str], signature: Signature) -> Optional[MatchResult]:
        """Match a single signature against the target."""
        detection = signature.detection
        if not detection:
            return None
        
        # Route to appropriate detection method
        if detection.type == DetectionType.PORT:
            return self._match_port(target, ports, services, signature)
        elif detection.type == DetectionType.BANNER:
            return self._match_banner(target, ports, banners, signature)
        elif detection.type == DetectionType.HTTP:
            return self._match_http(target, ports, signature)
        elif detection.type == DetectionType.CREDENTIAL:
            return self._match_credential(target, ports, services, signature)
        elif detection.type == DetectionType.VERSION:
            return self._match_version(target, ports, banners, signature)
        
        return None
    
    def _match_port(self, target: str, ports: List[int], services: Dict[int, str],
                    signature: Signature) -> Optional[MatchResult]:
        """Match based on open port and service."""
        detection = signature.detection
        
        # Check if specific port matches
        if detection.port and detection.port in ports:
            service = services.get(detection.port, 'unknown')
            return MatchResult(
                signature=signature,
                matched=True,
                confidence=0.8,  # Port match is fairly confident
                evidence=[f"Port {detection.port} is open"],
                target=target,
                port=detection.port,
                service=service
            )
        
        # Check if service name matches
        if detection.service:
            for port, service in services.items():
                if detection.service.lower() in service.lower():
                    return MatchResult(
                        signature=signature,
                        matched=True,
                        confidence=0.9,
                        evidence=[f"Service '{service}' detected on port {port}"],
                        target=target,
                        port=port,
                        service=service
                    )
        
        return None
    
    def _match_banner(self, target: str, ports: List[int], banners: Dict[int, str],
                      signature: Signature) -> Optional[MatchResult]:
        """Match based on service banner."""
        detection = signature.detection
        
        # Check specific port or all ports
        ports_to_check = [detection.port] if detection.port else list(banners.keys())
        
        for port in ports_to_check:
            if port not in banners:
                continue
            
            banner = banners[port]
            
            # Check match patterns
            for pattern in detection.match_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    return MatchResult(
                        signature=signature,
                        matched=True,
                        confidence=0.85,
                        evidence=[f"Banner matched pattern: {pattern}", f"Banner: {banner[:100]}..."],
                        target=target,
                        port=port,
                        service=banner.split()[0] if banner else 'unknown'
                    )
        
        return None
    
    def _match_http(self, target: str, ports: List[int], signature: Signature) -> Optional[MatchResult]:
        """Match based on HTTP request/response (simplified - no actual injection)."""
        detection = signature.detection
        
        # Check common HTTP ports
        http_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8000, 3000]]
        
        if not http_ports:
            return None
        
        for port in http_ports:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}{detection.path or '/'}"
            
            try:
                # Simple GET request to check if server is vulnerable type
                # In a real implementation, we would actually test payloads
                # Here we just check for common vulnerable patterns
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(url, headers={'User-Agent': 'RedShield/1.0'})
                response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
                content = response.read(4096).decode('utf-8', errors='ignore')
                
                # Check for vulnerable patterns in response
                for pattern in detection.match_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return MatchResult(
                            signature=signature,
                            matched=True,
                            confidence=0.7,  # Lower confidence without actual exploit
                            evidence=[f"Potential vulnerability pattern found: {pattern}"],
                            target=target,
                            port=port,
                            service='http'
                        )
                        
            except (urllib.error.URLError, socket.timeout, ssl.SSLError):
                pass
            except Exception:
                pass
        
        return None
    
    def _match_credential(self, target: str, ports: List[int], services: Dict[int, str],
                          signature: Signature) -> Optional[MatchResult]:
        """Match based on default credentials (placeholder - safe implementation)."""
        # This is a placeholder that doesn't actually try credentials
        # In a real implementation, this would test default credentials
        # against services like databases, SSH, web admin panels
        
        detection = signature.detection
        
        # Just flag common services that often have default credentials
        vulnerable_services = ['mongodb', 'mysql', 'redis', 'postgres', 'ssh', 'ftp']
        
        for port, service in services.items():
            if any(vs in service.lower() for vs in vulnerable_services):
                return MatchResult(
                    signature=signature,
                    matched=True,
                    confidence=0.5,  # Lower confidence - just a warning
                    evidence=[f"Service '{service}' may have default credentials"],
                    target=target,
                    port=port,
                    service=service,
                    details={'warning': 'Manual credential check recommended'}
                )
        
        return None
    
    def _match_version(self, target: str, ports: List[int], banners: Dict[int, str],
                       signature: Signature) -> Optional[MatchResult]:
        """Match based on version comparison."""
        # Extract versions from banners and compare
        version_patterns = [
            r'(\d+\.\d+(?:\.\d+)?)',  # Simple version: 1.2.3
            r'v(\d+\.\d+(?:\.\d+)?)',  # v1.2.3
        ]
        
        for port, banner in banners.items():
            for pattern in version_patterns:
                match = re.search(pattern, banner)
                if match:
                    # In a real implementation, we would check against known vulnerable versions
                    # For now, just flag if version info is found (potential for checking)
                    pass
        
        return None
    
    def _collect_banners(self, target: str, ports: List[int]) -> Dict[int, str]:
        """Collect service banners from open ports."""
        banners = {}
        
        for port in ports:
            if port in self._banner_cache.get(target, {}):
                banners[port] = self._banner_cache[target][port]
                continue
            
            try:
                banner = self._grab_banner(target, port)
                if banner:
                    banners[port] = banner
                    if target not in self._banner_cache:
                        self._banner_cache[target] = {}
                    self._banner_cache[target][port] = banner
            except Exception:
                pass
        
        return banners
    
    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Grab service banner from a port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Try to receive banner
            try:
                # Send a simple probe for HTTP
                if port in [80, 8080, 8000, 3000]:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port in [443, 8443]:
                    # For SSL ports, we'd need SSL wrapping
                    pass
                else:
                    sock.send(b"\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()
            except socket.timeout:
                return None
            finally:
                sock.close()
                
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        
        return None


class DetectionEngine:
    """
    High-level detection engine that coordinates scanning.
    
    This is the main interface for vulnerability detection.
    """
    
    def __init__(self, signatures: List[Signature] = None):
        from .loader import SignatureLoader
        
        if signatures is None:
            loader = SignatureLoader()
            signatures = loader.get_all()
        
        self.signatures = signatures
        self.matcher = SignatureMatcher(signatures)
    
    def scan(self, target: str, open_ports: List[Tuple[int, str]]) -> List[Dict[str, Any]]:
        """
        Scan a target for vulnerabilities.
        
        Args:
            target: IP address or hostname
            open_ports: List of (port, service) tuples from nmap scan
            
        Returns:
            List of vulnerability dictionaries
        """
        ports = [p[0] for p in open_ports]
        services = {p[0]: p[1] for p in open_ports}
        
        results = self.matcher.scan(target, ports, services)
        
        return [r.to_vulnerability() for r in results]
    
    def get_signatures_for_service(self, service: str) -> List[Signature]:
        """Get relevant signatures for a service."""
        relevant = []
        service_lower = service.lower()
        
        for sig in self.signatures:
            if sig.detection:
                if sig.detection.service and sig.detection.service.lower() in service_lower:
                    relevant.append(sig)
                elif any(tag.lower() in service_lower for tag in sig.tags):
                    relevant.append(sig)
        
        return relevant
