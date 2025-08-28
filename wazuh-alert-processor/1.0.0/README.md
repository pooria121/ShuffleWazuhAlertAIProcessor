# Wazuh Alert Processor

Processes Wazuh security alerts by categorizing them and enriching with Claude AI analysis.

## Features

- **Auto-categorization**: Assigns alerts to 10 predefined security categories
- **AI Analysis**: Uses Claude AI to provide human interpretation and analyst recommendations
- **Priority Assignment**: Recommends alert priority levels
- **Action Items**: Generates specific investigation tasks for analysts

## Categories

1. Authentication
2. Network Security  
3. Malware
4. Data Exfiltration
5. Privilege Escalation
6. System Integrity
7. Compliance
8. Threat Intelligence
9. Application Security
10. Endpoint Security

## Usage

### Action: `process_alert`

**Parameters:**
- `alert_json`: Wazuh alert JSON (string)
- `claude_api_key`: Your Claude API key (string)

**Returns:**
- `success`: Boolean indicating success
- `enriched_alert`: JSON string with added enrichment data
- `error`: Error message if processing failed

### Example Output

The app adds an "enrichment" section to your original alert:

```json
{
  "enrichment": {
    "category": "Authentication",
    "human_interpretation": "Failed SSH login attempt detected...",
    "analyst_todo_list": [
      "Check for brute force patterns",
      "Review source IP reputation"
    ],
    "recommended_priority": "Medium",
    "containment_actions": ["Monitor for continued attempts"]
  }
}
```

## Deployment

This app follows the Shuffle python-apps structure and can be deployed via GitHub integration in Shuffle SOAR.