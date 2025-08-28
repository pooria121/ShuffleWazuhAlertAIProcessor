#!/usr/bin/env python3
"""Test script for Wazuh Alert Processor Shuffle App."""

import json
import sys
import os

# Mock the walkoff_app_sdk for testing purposes
class MockAppBase:
    def __init__(self, redis=None, logger=None):
        self.logger = MockLogger()

class MockLogger:
    def error(self, msg):
        print(f"ERROR: {msg}")
    def info(self, msg):
        print(f"INFO: {msg}")

def action(*args, **kwargs):
    """Mock action decorator."""
    def decorator(func):
        return func
    
    if len(args) == 1 and callable(args[0]):
        # Used as @action without arguments
        return args[0]
    else:
        # Used as @action() with arguments
        return decorator

# Mock the modules
sys.modules['walkoff_app_sdk'] = type('module', (), {})()
sys.modules['walkoff_app_sdk.app_base'] = type('module', (), {'AppBase': MockAppBase})()
sys.modules['walkoff_app_sdk.action_api'] = type('module', (), {'action': action})()

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from app import WazuhAlertProcessor

def test_categorization():
    """Test alert categorization."""
    app = WazuhAlertProcessor()
    
    test_alert = {
        "severity": 2,
        "title": "PAM: User login failed.",
        "rule_id": "5503",
        "timestamp": "2025-08-28T00:24:20.173+0000",
        "all_fields": {
            "rule": {
                "description": "PAM: User login failed.",
                "groups": ["pam", "authentication_failed"],
                "mitre": {"tactic": ["Credential Access"], "technique": ["Password Guessing"]}
            },
            "agent": {"name": "test-agent", "ip": "1.2.3.4"},
            "full_log": "authentication failure ssh"
        }
    }
    
    category = app.categorize_alert(test_alert)
    print(f"Test Alert Categorized as: {category}")
    
    expected = "Authentication"
    if category == expected:
        print("PASS: Categorization test passed")
        return True
    else:
        print(f"FAIL: Expected {expected}, got {category}")
        return False

def test_claude_analysis_structure():
    """Test Claude analysis structure without API call."""
    app = WazuhAlertProcessor()
    
    test_alert = {
        "all_fields": {
            "rule": {
                "id": "5503",
                "description": "Test alert",
                "level": 5,
                "groups": ["test"],
                "mitre": {"tactic": ["Test"], "technique": ["Test"]}
            },
            "agent": {"name": "test-agent", "ip": "1.2.3.4"},
            "full_log": "Test log entry"
        },
        "timestamp": "2025-08-28T00:00:00.000Z"
    }
    
    # Test with invalid API key (will use fallback)
    result = app.get_claude_analysis(test_alert, "invalid-key")
    
    required_keys = ["human_interpretation", "analyst_todo_list", "recommended_priority", "containment_actions", "full_analysis"]
    
    for key in required_keys:
        if key not in result:
            print(f"FAIL: Missing {key} in Claude analysis")
            return False
    
    if isinstance(result.get("analyst_todo_list"), list):
        print("PASS: Claude analysis structure test passed")
        print(f"Interpretation: {result['human_interpretation'][:50]}...")
        return True
    else:
        print("FAIL: analyst_todo_list is not a list")
        return False

def main():
    """Run tests for the restructured Shuffle app."""
    print("Testing Shuffle-structured Wazuh Alert Processor")
    print("=" * 50)
    
    tests = [test_categorization, test_claude_analysis_structure]
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"FAIL: Test {test.__name__} threw exception: {e}")
            failed += 1
        print()
    
    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("SUCCESS: App is ready for Shuffle deployment!")
        return 0
    else:
        print("ERROR: Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())