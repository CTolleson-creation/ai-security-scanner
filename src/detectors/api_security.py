"""
API Security Detector
Scans code and configuration files for exposed API keys and credentials
"""

import re
import json
from typing import List, Dict
from pathlib import Path


class APISecurityDetector:
    """
    Detects exposed API keys and credentials in code and config files
    """
    
    def __init__(self):
        """Initialize the API security detector with common patterns"""
        # Common API key patterns to detect
        self.patterns = {
            'openai_key': {
                'pattern': r'sk-[a-zA-Z0-9]{48}',
                'description': 'OpenAI API Key',
                'severity': 'CRITICAL'
            },
            'anthropic_key': {
                'pattern': r'sk-ant-[a-zA-Z0-9\-]{95,}',
                'description': 'Anthropic API Key',
                'severity': 'CRITICAL'
            },
            'generic_api_key': {
                'pattern': r'api[_-]?key["\s:=]+["\']?[a-zA-Z0-9]{20,}["\']?',
                'description': 'Generic API Key',
                'severity': 'HIGH'
            },
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS Access Key',
                'severity': 'CRITICAL'
            },
            'github_token': {
                'pattern': r'ghp_[a-zA-Z0-9]{36}',
                'description': 'GitHub Personal Access Token',
                'severity': 'CRITICAL'
            },
            'password_in_code': {
                'pattern': r'password["\s:=]+["\'][^"\']{8,}["\']',
                'description': 'Hardcoded Password',
                'severity': 'HIGH'
            },
            'bearer_token': {
                'pattern': r'Bearer\s+[a-zA-Z0-9\-._~+/]+=*',
                'description': 'Bearer Token',
                'severity': 'HIGH'
            }
        }
    
    def scan_text(self, text: str, source: str = "input") -> List[Dict]:
        """
        Scan text content for exposed API keys and credentials
        
        Args:
            text: Text content to scan
            source: Source identifier (filename, URL, etc.)
            
        Returns:
            List of findings with details
        """
        findings = []
        
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.finditer(pattern_info['pattern'], text, re.IGNORECASE)
            
            for match in matches:
                # Extract the matched credential (masked for safety)
                matched_text = match.group(0)
                masked_value = self._mask_credential(matched_text)
                
                # Get line number where credential was found
                line_num = text[:match.start()].count('\n') + 1
                
                finding = {
                    'type': 'EXPOSED_CREDENTIAL',
                    'severity': pattern_info['severity'],
                    'credential_type': pattern_info['description'],
                    'location': source,
                    'line_number': line_num,
                    'matched_value': masked_value,
                    'recommendation': self._get_recommendation(pattern_name)
                }
                
                findings.append(finding)
        
        return findings
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a specific file for exposed credentials
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                return self.scan_text(content, source=file_path)
        except Exception as e:
            return [{
                'type': 'SCAN_ERROR',
                'severity': 'INFO',
                'message': f"Could not scan {file_path}: {str(e)}"
            }]
    
    def scan_directory(self, directory_path: str, 
                       extensions: List[str] = None) -> List[Dict]:
        """
        Recursively scan a directory for exposed credentials
        
        Args:
            directory_path: Path to directory to scan
            extensions: List of file extensions to scan (e.g., ['.py', '.js', '.env'])
            
        Returns:
            List of all findings across all files
        """
        if extensions is None:
            # Default extensions to scan
            extensions = ['.py', '.js', '.ts', '.json', '.yaml', '.yml', 
                         '.env', '.config', '.sh', '.bash']
        
        all_findings = []
        directory = Path(directory_path)
        
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix in extensions:
                # Skip common directories that shouldn't be scanned
                if any(skip in str(file_path) for skip in ['venv', 'node_modules', '.git']):
                    continue
                
                findings = self.scan_file(str(file_path))
                all_findings.extend(findings)
        
        return all_findings
    
    def _mask_credential(self, credential: str) -> str:
        """
        Mask a credential for safe display
        
        Args:
            credential: The credential to mask
            
        Returns:
            Masked version showing only first/last few characters
        """
        if len(credential) <= 8:
            return "***"
        
        # Show first 4 and last 4 characters
        return f"{credential[:4]}...{credential[-4:]}"
    
    def _get_recommendation(self, pattern_name: str) -> str:
        """
        Get remediation recommendation for a specific credential type
        
        Args:
            pattern_name: Name of the pattern that matched
            
        Returns:
            Remediation recommendation
        """
        recommendations = {
            'openai_key': "Move OpenAI API key to environment variables (.env file). Use python-dotenv to load it securely.",
            'anthropic_key': "Store Anthropic API key in environment variables. Never commit .env files to version control.",
            'generic_api_key': "Remove hardcoded API key. Use environment variables or a secrets management service.",
            'aws_access_key': "URGENT: Rotate this AWS key immediately. Use AWS IAM roles or environment variables instead.",
            'github_token': "Remove GitHub token from code. Use GitHub Secrets for CI/CD or environment variables locally.",
            'password_in_code': "Remove hardcoded password. Use secure password storage or OAuth authentication.",
            'bearer_token': "Remove bearer token from code. Tokens should be obtained at runtime, not hardcoded."
        }
        
        return recommendations.get(pattern_name, 
                                  "Remove this credential from code. Use environment variables or a secrets manager.")


def run_api_security_scan(target: str, is_file: bool = False) -> Dict:
    """
    Convenience function to run API security scan
    
    Args:
        target: Text content, file path, or directory path
        is_file: Whether target is a file/directory path
        
    Returns:
        Scan results with findings and summary
    """
    detector = APISecurityDetector()
    
    if is_file:
        if Path(target).is_dir():
            findings = detector.scan_directory(target)
        else:
            findings = detector.scan_file(target)
    else:
        findings = detector.scan_text(target, source="text_input")
    
    # Calculate summary statistics
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    for finding in findings:
        severity = finding.get('severity', 'LOW')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return {
        'findings': findings,
        'total_findings': len(findings),
        'severity_breakdown': severity_counts,
        'scan_target': target
    }