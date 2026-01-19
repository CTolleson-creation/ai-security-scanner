"""
Simple demo script to test the AI Security Scanner
Runs prompt injection tests against a mock LLM
"""

from src.detectors.prompt_injection import PromptInjectionDetector
from src.mock_llm import MockLLM

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def print_result(result):
    """Print a single test result"""
    status = "🚨 VULNERABLE" if result["vulnerable"] else "✅ SECURE"
    severity = result["severity"]
    
    print(f"{status} | {severity} | {result['test_id']} - {result['category']}")
    print(f"   Payload: {result['payload'][:80]}...")
    
    if result["vulnerable"]:
        print(f"   ⚠️  Response: {result['response_snippet'][:100]}...")
    
    print()

def run_demo():
    """Run the security scanner demo"""
    
    print_header("AI Security Scanner - Demo Mode")
    
    # Initialize components
    print("🔧 Initializing scanner...")
    detector = PromptInjectionDetector()
    
    # Test against VULNERABLE LLM (shows what vulnerabilities look like)
    print("\n📍 Testing against VULNERABLE LLM (simulated insecure AI)")
    print("   This simulates an AI with poor security controls\n")
    
    vulnerable_llm = MockLLM(vulnerability_mode="vulnerable")
    vulnerable_results = []
    
    test_cases = detector.get_test_payloads()
    
    for test_case in test_cases:
        # Send payload to mock LLM
        response = vulnerable_llm.generate_response(test_case["payload"])
        
        # Analyze the response
        result = detector.analyze_response(test_case, response)
        vulnerable_results.append(result)
        
        print_result(result)
    
    # Generate summary
    print_header("Vulnerability Summary - VULNERABLE LLM")
    summary = detector.generate_report_summary(vulnerable_results)
    
    print(f"Total Tests Run: {summary['total_tests']}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    print(f"Security Score: {summary['security_score']}/100")
    print(f"\nBy Severity:")
    print(f"  🔴 CRITICAL: {summary['by_severity']['CRITICAL']}")
    print(f"  🟠 HIGH: {summary['by_severity']['HIGH']}")
    print(f"  🟡 MEDIUM: {summary['by_severity']['MEDIUM']}")
    print(f"  🟢 LOW: {summary['by_severity']['LOW']}")
    
    # Now test against SECURE LLM (shows proper security)
    print("\n" + "="*70)
    print("\n📍 Testing against SECURE LLM (simulated secure AI)")
    print("   This simulates an AI with proper security controls\n")
    
    secure_llm = MockLLM(vulnerability_mode="secure")
    secure_results = []
    
    for test_case in test_cases:
        response = secure_llm.generate_response(test_case["payload"])
        result = detector.analyze_response(test_case, response)
        secure_results.append(result)
        print_result(result)
    
    # Generate summary
    print_header("Vulnerability Summary - SECURE LLM")
    summary = detector.generate_report_summary(secure_results)
    
    print(f"Total Tests Run: {summary['total_tests']}")
    print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
    print(f"Security Score: {summary['security_score']}/100")
    print(f"\nBy Severity:")
    print(f"  🔴 CRITICAL: {summary['by_severity']['CRITICAL']}")
    print(f"  🟠 HIGH: {summary['by_severity']['HIGH']}")
    print(f"  🟡 MEDIUM: {summary['by_severity']['MEDIUM']}")
    print(f"  🟢 LOW: {summary['by_severity']['LOW']}")
    
    print_header("Demo Complete!")
    print("✨ This demonstrates how the scanner detects vulnerabilities")
    print("📊 Next: Build Streamlit interface for interactive testing")
    print("🔑 Later: Connect to real LLM APIs (OpenAI, Anthropic)")

if __name__ == "__main__":
    run_demo()