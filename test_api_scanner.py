"""
Test script for API Security Scanner
"""

from src.detectors.api_security import run_api_security_scan
import json


def test_exposed_keys():
    """Test detection of various exposed credentials"""
    
    # Example code with exposed credentials (FAKE keys for testing)
    test_code = """
    # Bad practice - hardcoded API keys
    openai_api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"
    anthropic_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDE"
    
    # More bad practices
    config = {
        "api_key": "my_secret_key_12345678901234567890",
        "password": "SuperSecret123!",
        "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    }
    
    # AWS credentials (don't do this!)
    AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    """
    
    print("="*60)
    print("🔍 API Security Scanner Test")
    print("="*60)
    
    # Run the scan
    results = run_api_security_scan(test_code, is_file=False)
    
    print(f"\n📊 Scan Results:")
    print(f"Total Findings: {results['total_findings']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in results['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print(f"\n🚨 Detailed Findings:\n")
    
    for i, finding in enumerate(results['findings'], 1):
        print(f"{i}. {finding['credential_type']}")
        print(f"   Severity: {finding['severity']}")
        print(f"   Location: Line {finding['line_number']}")
        print(f"   Matched: {finding['matched_value']}")
        print(f"   Fix: {finding['recommendation']}")
        print()


if __name__ == "__main__":
    test_exposed_keys()