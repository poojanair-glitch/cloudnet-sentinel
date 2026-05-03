import json
import time
import boto3
import os

# Configuration
DYNAMODB_TABLE = os.environ.get('TIMELINE_TABLE', 'SentinelAttackTimeline')
SENSITIVE_ACTIONS = ['GetObject', 'DeleteBucket', 'PutBucketPolicy', 'AuthorizeSecurityGroupIngress']
ESCALATION_ACTIONS = ['AssumeRole', 'UpdateAssumeRolePolicy', 'CreatePolicyVersion']

db = boto3.resource('dynamodb')
table = db.Table(DYNAMODB_TABLE)

def handler(event, context):
    """
    AWS Lambda Handler for EventBridge CloudTrail Events
    """
    detail = event.get('detail', {})
    event_name = detail.get('eventName')
    user_identity = detail.get('userIdentity', {})
    principal_id = user_identity.get('principalId')
    event_time = detail.get('eventTime')
    request_parameters = detail.get('requestParameters', {})

    print(f"Processing Event: {event_name} from Principal: {principal_id}")

    # 1. Update/Retrieve State for this Principal
    state = get_principal_state(principal_id)
    
    # 2. Sequence Detection Logic
    detection = analyze_sequence(state, event_name, detail)
    
    # 3. Update Timeline in Structured Format
    update_timeline(principal_id, event_name, event_time, detail, detection)

    return {
        'statusCode': 200,
        'body': json.dumps({'detected': bool(detection)})
    }

def get_principal_state(principal_id):
    try:
        response = table.get_item(Key={'principalId': principal_id})
        return response.get('Item', {'principalId': principal_id, 'sequence': [], 'risk_score': 0})
    except:
        return {'principalId': principal_id, 'sequence': [], 'risk_score': 0}

def analyze_sequence(state, current_event, detail):
    sequence = state.get('sequence', [])
    sequence.append(current_event)
    
    # Keep only last 10 events for memory efficiency
    if len(sequence) > 10: sequence.pop(0)
    
    findings = []
    
    # Pattern 1: ConsoleLogin -> Escalation -> Data Access
    if len(sequence) >= 3:
        has_login = 'ConsoleLogin' in sequence
        has_escalation = any(e in sequence for e in ESCALATION_ACTIONS)
        has_data_access = any(e in sequence for e in SENSITIVE_ACTIONS)
        
        if has_login and has_escalation and has_data_access:
            findings.append("Suspicious Sequence: Login -> Escalation -> Sensitive Action")

    # Pattern 2: Rapid Sensitive Actions (Potential Exfiltration)
    recent_sensitive = [e for e in sequence[-5:] if e in SENSITIVE_ACTIONS]
    if len(recent_sensitive) >= 3:
        findings.append("Anomalous Activity: Rapid succession of sensitive actions")

    state['sequence'] = sequence
    if findings:
        state['risk_score'] += 25
        return findings
    return None

def update_timeline(principal_id, event_name, event_time, detail, detection):
    item = {
        'principalId': principal_id,
        'lastEvent': event_name,
        'timestamp': event_time,
        'detail': json.dumps(detail),
        'alert': detection if detection else "None"
    }
    
    # Store in DynamoDB for real-time state
    table.put_item(Item=item)
    
    # Structured Logging for SIEM/Audit
    if detection:
        print(json.dumps({
            'level': 'ALERT',
            'principal': principal_id,
            'detection': detection,
            'event': event_name,
            'time': event_time
        }))
