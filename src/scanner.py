from src.scoring import SecurityScorer

"""
Main AI Security Scanner
Orchestrates all security detectors and generates comprehensive reports
"""

import json
from typing import Dict, List
from datetime import datetime

from src.detectors.prompt_injection import PromptInjectionDetector
from src.detectors.api_security import APISecurityDetector


class AISecurityScanner:
    """
    Main scanner class that coordinates all security checks
    """
    
    def __init__(self):
        """Initialize all security detectors"""
        self.prompt_detector = PromptInjectionDetector()
        self.api_detector = APISecurityDetector()
        
    def scan_prompt(self, prompt: str, response: str = None) -> Dict:
        """
        Scan a prompt for injection attempts
        
        Args:
            prompt: The prompt to scan
            response: Optional LLM response to analyze
            
        Returns:
            Scan results
        """
        result = self.prompt_detector.detect(prompt, response)
        
        return {
            'scan_type': 'PROMPT_INJECTION',
            'timestamp': datetime.now().isoformat(),
            'result': result
        }
    
    def scan_api_security(self, target: str, is_file: bool = False) -> Dict:
        """
        Scan for exposed API keys and credentials
        
        Args:
            target: Text, file path, or directory to scan
            is_file: Whether target is a file/directory
            
        Returns:
            Scan results
        """
        if is_file:
            from pathlib import Path
            if Path(target).is_dir():
                findings = self.api_detector.scan_directory(target)
            else:
                findings = self.api_detector.scan_file(target)
        else:
            findings = self.api_detector.scan_text(target, source="text_input")
        
        # Calculate severity breakdown
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
            'scan_type': 'API_SECURITY',
            'timestamp': datetime.now().isoformat(),
            'findings': findings,
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'target': target
        }
    
    def comprehensive_scan(self, target_config: Dict) -> Dict:
        """
        Run a comprehensive security scan with multiple detectors
        
        Args:
            target_config: Configuration specifying what to scan
                {
                    'prompts': [list of prompts to test],
                    'code_directory': 'path/to/code',
                    'config_files': ['path/to/config1', 'path/to/config2']
                }
        
        Returns:
            Comprehensive scan results with security score
        """
        all_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'scans_performed': [],
            'total_findings': 0,
            'severity_summary': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # Scan prompts if provided
        if 'prompts' in target_config:
            for prompt in target_config['prompts']:
                result = self.scan_prompt(prompt)
                all_results['scans_performed'].append(result)
                
                # Update severity counts
                if result['result']['is_malicious']:
                    severity = result['result']['severity']
                    all_results['severity_summary'][severity] += 1
                    all_results['total_findings'] += 1
        
        # Scan code directory if provided
        if 'code_directory' in target_config:
            result = self.scan_api_security(
                target_config['code_directory'], 
                is_file=True
            )
            all_results['scans_performed'].append(result)
            
            # Update severity counts
            for severity, count in result['severity_breakdown'].items():
                all_results['severity_summary'][severity] += count
            all_results['total_findings'] += result['total_findings']
        
        # Scan individual config files if provided
        if 'config_files' in target_config:
            for config_file in target_config['config_files']:
                result = self.scan_api_security(config_file, is_file=True)
                all_results['scans_performed'].append(result)
                
                # Update severity counts
                for severity, count in result['severity_breakdown'].items():
                    all_results['severity_summary'][severity] += count
                all_results['total_findings'] += result['total_findings']
        
        # Calculate security score
        scorer = SecurityScorer()
        all_results['security_score'] = scorer.calculate_score(
            all_results['severity_summary']
        )
        
        return all_results
    
    def generate_summary(self, scan_results: Dict) -> str:
        """
        Generate a human-readable summary of scan results
        
        Args:
            scan_results: Results from comprehensive_scan()
            
        Returns:
            Formatted summary string
        """
        summary = []
        summary.append("="*60)
        summary.append("🔒 AI Security Scan Summary")
        summary.append("="*60)
        summary.append(f"Scan Time: {scan_results['scan_timestamp']}")
        summary.append(f"Total Scans: {len(scan_results['scans_performed'])}")
        summary.append(f"Total Findings: {scan_results['total_findings']}")
        summary.append("")
        summary.append("Severity Breakdown:")
        
        for severity, count in scan_results['severity_summary'].items():
            if count > 0:
                emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(severity, '⚪')
                summary.append(f"  {emoji} {severity}: {count}")
        
        summary.append("")
        summary.append("="*60)
        
        return "\n".join(summary)