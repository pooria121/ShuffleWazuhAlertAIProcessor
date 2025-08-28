import asyncio
import json
import requests
from walkoff_app_sdk.app_base import AppBase
from walkoff_app_sdk.action_api import action


class WazuhAlertProcessor(AppBase):
    __version__ = "1.0.0"
    app_name = "wazuh-alert-processor"

    def __init__(self, redis=None, logger=None):
        super().__init__(redis, logger)
        self.categories = {
            "Authentication": {
                "keywords": ["authentication", "login", "pam", "ssh", "auth", "credential", "password"],
                "mitre_tactics": ["Credential Access", "Initial Access"],
                "rule_groups": ["authentication_failed", "authentication_success", "pam", "sshd"]
            },
            "Network Security": {
                "keywords": ["network", "connection", "port", "scan", "firewall", "traffic"],
                "mitre_tactics": ["Discovery", "Lateral Movement", "Command and Control"],
                "rule_groups": ["firewall", "network", "portscan", "ids"]
            },
            "Malware": {
                "keywords": ["virus", "malware", "trojan", "suspicious", "malicious", "rootkit"],
                "mitre_tactics": ["Execution", "Defense Evasion", "Persistence"],
                "rule_groups": ["malware", "virus", "rootkit", "suspicious_process"]
            },
            "Data Exfiltration": {
                "keywords": ["file", "transfer", "upload", "download", "data", "exfiltration"],
                "mitre_tactics": ["Exfiltration", "Collection"],
                "rule_groups": ["file_transfer", "data_loss", "ftp", "web_upload"]
            },
            "Privilege Escalation": {
                "keywords": ["sudo", "privilege", "escalation", "admin", "root", "elevation"],
                "mitre_tactics": ["Privilege Escalation"],
                "rule_groups": ["privilege_escalation", "sudo", "admin_activity"]
            },
            "System Integrity": {
                "keywords": ["file", "modification", "change", "integrity", "configuration"],
                "mitre_tactics": ["Impact", "Defense Evasion"],
                "rule_groups": ["file_integrity", "config_change", "system_modification"]
            },
            "Compliance": {
                "keywords": ["compliance", "policy", "violation", "audit", "regulation"],
                "mitre_tactics": [],
                "rule_groups": ["compliance", "policy_violation", "audit"]
            },
            "Threat Intelligence": {
                "keywords": ["threat", "intelligence", "ioc", "blacklist", "reputation"],
                "mitre_tactics": ["Reconnaissance"],
                "rule_groups": ["threat_intel", "blacklist", "reputation"]
            },
            "Application Security": {
                "keywords": ["web", "http", "sql", "injection", "xss", "application"],
                "mitre_tactics": ["Initial Access", "Execution"],
                "rule_groups": ["web_attack", "sql_injection", "xss", "web_application"]
            },
            "Endpoint Security": {
                "keywords": ["process", "endpoint", "host", "registry"],
                "mitre_tactics": ["Execution", "Persistence", "Defense Evasion"],
                "rule_groups": ["process_monitor", "registry", "endpoint", "host_based"]
            }
        }

    def categorize_alert(self, alert):
        """Categorize a Wazuh alert based on its content."""
        try:
            # Parse alert if it's a string
            if isinstance(alert, str):
                alert = json.loads(alert)
            
            # Extract relevant fields for categorization
            rule_description = alert.get("all_fields", {}).get("rule", {}).get("description", "").lower()
            rule_groups = alert.get("all_fields", {}).get("rule", {}).get("groups", [])
            mitre_tactics = []
            
            if "all_fields" in alert and "rule" in alert["all_fields"] and "mitre" in alert["all_fields"]["rule"]:
                mitre_tactics = alert["all_fields"]["rule"]["mitre"].get("tactic", [])
            
            full_log = alert.get("all_fields", {}).get("full_log", "").lower()
            
            # Score each category
            category_scores = {}
            
            for category, criteria in self.categories.items():
                score = 0
                
                # Check keywords in description and log
                for keyword in criteria["keywords"]:
                    if keyword in rule_description:
                        score += 2
                    if keyword in full_log:
                        score += 1
                
                # Check MITRE tactics
                for tactic in criteria["mitre_tactics"]:
                    if tactic in mitre_tactics:
                        score += 3
                
                # Check rule groups
                for group in criteria["rule_groups"]:
                    if group in rule_groups:
                        score += 4
                
                category_scores[category] = score
            
            # Return the category with the highest score
            best_category = max(category_scores, key=category_scores.get)
            
            # If no category scored above 0, assign "Other"
            if category_scores[best_category] == 0:
                return "Other"
            
            return best_category
            
        except Exception as e:
            self.logger.error(f"Error categorizing alert: {str(e)}")
            return "Unknown"

    def get_claude_analysis(self, alert, claude_api_key):
        """Get human interpretation and analyst recommendations from Claude API."""
        try:
            # Prepare the alert summary for Claude
            rule_info = alert.get("all_fields", {}).get("rule", {})
            agent_info = alert.get("all_fields", {}).get("agent", {})
            
            alert_summary = f"""
            Security Alert Analysis Request:
            
            Rule ID: {rule_info.get('id', 'N/A')}
            Description: {rule_info.get('description', 'N/A')}
            Severity Level: {rule_info.get('level', 'N/A')}
            MITRE Tactics: {', '.join(rule_info.get('mitre', {}).get('tactic', []))}
            MITRE Techniques: {', '.join(rule_info.get('mitre', {}).get('technique', []))}
            Groups: {', '.join(rule_info.get('groups', []))}
            
            Agent: {agent_info.get('name', 'N/A')} ({agent_info.get('ip', 'N/A')})
            Timestamp: {alert.get('timestamp', 'N/A')}
            
            Full Log: {alert.get('all_fields', {}).get('full_log', 'N/A')}
            
            Please provide:
            1. A human-readable interpretation of what this alert means
            2. Specific action items for security analysts to investigate
            3. Priority level recommendation (Critical/High/Medium/Low)
            4. Any immediate containment actions needed
            """
            
            headers = {
                "x-api-key": claude_api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01"
            }
            
            payload = {
                "model": "claude-3-sonnet-20240229",
                "max_tokens": 1000,
                "messages": [
                    {
                        "role": "user",
                        "content": alert_summary
                    }
                ]
            }
            
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                claude_response = response.json()
                analysis_text = claude_response["content"][0]["text"]
                
                # Parse the response to extract structured information
                lines = analysis_text.split('\n')
                interpretation = ""
                todo_list = []
                priority = "Medium"
                containment_actions = []
                
                current_section = None
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                        
                    if "interpretation" in line.lower() or "what this alert means" in line.lower():
                        current_section = "interpretation"
                        continue
                    elif "action items" in line.lower() or "investigate" in line.lower():
                        current_section = "todo"
                        continue
                    elif "priority" in line.lower():
                        current_section = "priority"
                        if any(p in line.lower() for p in ["critical", "high", "medium", "low"]):
                            for p in ["critical", "high", "medium", "low"]:
                                if p in line.lower():
                                    priority = p.title()
                                    break
                        continue
                    elif "containment" in line.lower() or "immediate" in line.lower():
                        current_section = "containment"
                        continue
                    
                    if current_section == "interpretation":
                        interpretation += line + " "
                    elif current_section == "todo" and (line.startswith("-") or line.startswith("•") or line.startswith("*") or line[0].isdigit()):
                        todo_list.append(line.lstrip("- •*0123456789. "))
                    elif current_section == "containment" and (line.startswith("-") or line.startswith("•") or line.startswith("*") or line[0].isdigit()):
                        containment_actions.append(line.lstrip("- •*0123456789. "))
                
                return {
                    "human_interpretation": interpretation.strip() or analysis_text[:500] + "...",
                    "analyst_todo_list": todo_list,
                    "recommended_priority": priority,
                    "containment_actions": containment_actions,
                    "full_analysis": analysis_text
                }
            else:
                return {
                    "human_interpretation": "Unable to get Claude analysis - API error",
                    "analyst_todo_list": ["Review alert manually", "Check system logs", "Investigate source IP"],
                    "recommended_priority": "Medium",
                    "containment_actions": [],
                    "full_analysis": f"API Error: {response.status_code}"
                }
                
        except Exception as e:
            self.logger.error(f"Error getting Claude analysis: {str(e)}")
            return {
                "human_interpretation": f"Error getting Claude analysis: {str(e)}",
                "analyst_todo_list": ["Review alert manually", "Check system logs"],
                "recommended_priority": "Medium", 
                "containment_actions": [],
                "full_analysis": f"Exception: {str(e)}"
            }

    @action
    def process_alert(self, alert_json, claude_api_key):
        """Process Wazuh alert - categorize and enrich with Claude analysis."""
        try:
            # Parse the input JSON
            alert = json.loads(alert_json) if isinstance(alert_json, str) else alert_json
            
            # Add categorization
            category = self.categorize_alert(alert)
            alert["enrichment"] = {
                "category": category,
                "processed_timestamp": alert.get("timestamp", "")
            }
            
            # Get Claude analysis
            claude_analysis = self.get_claude_analysis(alert, claude_api_key)
            alert["enrichment"].update(claude_analysis)
            
            return {
                "success": True,
                "enriched_alert": json.dumps(alert, indent=2)
            }
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "enriched_alert": ""
            }


if __name__ == "__main__":
    WazuhAlertProcessor.run()