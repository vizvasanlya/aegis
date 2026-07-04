"""
Evidence capture system for Aegis pentesting.

Handles:
- Automatic screenshot capture
- HTTP request/response logging
- Evidence organization per vulnerability
- Timestamp metadata
"""

import os
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime


class EvidenceCapture:
    """Captures and organizes evidence for vulnerabilities."""
    
    def __init__(self, scan_dir: str):
        self.scan_dir = Path(scan_dir)
        self.evidence_dir = self.scan_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def create_vuln_evidence_dir(self, vuln_id: str) -> Path:
        """Create evidence directory for a vulnerability."""
        vuln_dir = self.evidence_dir / vuln_id
        vuln_dir.mkdir(parents=True, exist_ok=True)
        (vuln_dir / "screenshots").mkdir(exist_ok=True)
        (vuln_dir / "requests").mkdir(exist_ok=True)
        return vuln_dir
    
    def save_screenshot(self, vuln_id: str, screenshot_data: bytes, 
                        filename: str, description: str = "") -> str:
        """Save a screenshot with metadata."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        screenshot_path = vuln_dir / "screenshots" / filename
        
        # Save screenshot
        with open(screenshot_path, "wb") as f:
            f.write(screenshot_data)
        
        # Save metadata
        metadata = {
            "filename": filename,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "size_bytes": len(screenshot_data),
            "hash_sha256": hashlib.sha256(screenshot_data).hexdigest(),
        }
        
        meta_path = screenshot_path.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        return str(screenshot_path)
    
    def save_http_evidence(self, vuln_id: str, request: Dict[str, Any], 
                           response: Dict[str, Any], description: str = "") -> str:
        """Save HTTP request/response evidence."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"request_{timestamp}.txt"
        evidence_path = vuln_dir / "requests" / filename
        
        # Format evidence
        evidence = f"""=== HTTP Evidence ===
Timestamp: {datetime.now().isoformat()}
Description: {description}

--- REQUEST ---
{request.get('method', 'GET')} {request.get('url', '')} HTTP/1.1
Host: {request.get('host', '')}
{chr(10).join(f'{k}: {v}' for k, v in request.get('headers', {}).items())}

{request.get('body', '')}

--- RESPONSE ---
HTTP/1.1 {response.get('status_code', '')} {response.get('status_text', '')}
{chr(10).join(f'{k}: {v}' for k, v in response.get('headers', {}).items())}

{response.get('body', '')[:5000]}
"""
        
        with open(evidence_path, "w") as f:
            f.write(evidence)
        
        # Save metadata
        metadata = {
            "filename": filename,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "request_url": request.get("url"),
            "request_method": request.get("method"),
            "response_status": response.get("status_code"),
            "hash_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
        }
        
        meta_path = evidence_path.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        return str(evidence_path)
    
    def save_poc(self, vuln_id: str, poc_code: str, poc_type: str = "python") -> str:
        """Save proof of concept code."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        
        if poc_type == "python":
            poc_path = vuln_dir / "poc.py"
        elif poc_type == "bash":
            poc_path = vuln_dir / "poc.sh"
        else:
            poc_path = vuln_dir / "poc.txt"
        
        with open(poc_path, "w") as f:
            f.write(poc_code)
        
        # Save metadata
        metadata = {
            "type": poc_type,
            "timestamp": datetime.now().isoformat(),
            "hash_sha256": hashlib.sha256(poc_code.encode()).hexdigest(),
        }
        
        meta_path = poc_path.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        return str(poc_path)
    
    def save_findings_summary(self, vuln_id: str, findings: Dict[str, Any]) -> str:
        """Save findings summary."""
        vuln_dir = self.create_vuln_evidence_dir(vuln_id)
        summary_path = vuln_dir / "findings.json"
        
        findings["timestamp"] = datetime.now().isoformat()
        findings["evidence_dir"] = str(vuln_dir)
        
        with open(summary_path, "w") as f:
            json.dump(findings, f, indent=2)
        
        return str(summary_path)
    
    def get_evidence_list(self, vuln_id: str) -> List[Dict[str, Any]]:
        """List all evidence for a vulnerability."""
        vuln_dir = self.evidence_dir / vuln_id
        if not vuln_dir.exists():
            return []
        
        evidence = []
        
        # Screenshots
        screenshots_dir = vuln_dir / "screenshots"
        if screenshots_dir.exists():
            for f in screenshots_dir.glob("*.png"):
                meta = f.with_suffix(".json")
                if meta.exists():
                    with open(meta) as mf:
                        evidence.append({"type": "screenshot", "path": str(f), **json.load(mf)})
        
        # Requests
        requests_dir = vuln_dir / "requests"
        if requests_dir.exists():
            for f in requests_dir.glob("*.txt"):
                meta = f.with_suffix(".json")
                if meta.exists():
                    with open(meta) as mf:
                        evidence.append({"type": "http_request", "path": str(f), **json.load(mf)})
        
        # PoC
        for ext in ["py", "sh", "txt"]:
            for f in vuln_dir.glob(f"poc.{ext}"):
                meta = f.with_suffix(".json")
                if meta.exists():
                    with open(meta) as mf:
                        evidence.append({"type": "poc", "path": str(f), **json.load(mf)})
        
        return sorted(evidence, key=lambda x: x.get("timestamp", ""))
    
    def calculate_evidence_hash(self, vuln_id: str) -> str:
        """Calculate hash of all evidence for a vulnerability."""
        evidence_list = self.get_evidence_list(vuln_id)
        combined_hash = hashlib.sha256()
        
        for item in evidence_list:
            if "hash_sha256" in item:
                combined_hash.update(item["hash_sha256"].encode())
        
        return combined_hash.hexdigest()


# Global evidence capture instance
_evidence_capture: Optional[EvidenceCapture] = None


def get_evidence_capture(scan_dir: str) -> EvidenceCapture:
    """Get or create evidence capture instance."""
    global _evidence_capture
    if _evidence_capture is None or str(_evidence_capture.scan_dir) != scan_dir:
        _evidence_capture = EvidenceCapture(scan_dir)
    return _evidence_capture
