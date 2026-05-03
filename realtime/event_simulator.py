import time
import random

class EventSimulator:
    def __init__(self):
        self.event_types = [
            {"type": "IAM_POLICY_CHANGE", "severity": "MEDIUM"},
            {"type": "EC2_LOGIN_SUCCESS", "severity": "LOW"},
            {"type": "SUSPICIOUS_S3_ACCESS", "severity": "HIGH"},
            {"type": "IAM_USER_CREATED", "severity": "MEDIUM"},
            {"type": "EC2_SG_MODIFIED", "severity": "HIGH"}
        ]

    def simulate_events(self, nodes):
        """
        Yields random simulated events mapped to existing nodes.
        """
        while True:
            event_base = random.choice(self.event_types)
            target_node = random.choice(list(nodes)) if nodes else "Unknown"
            
            event = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": event_base["type"],
                "severity": event_base["severity"],
                "node": target_node,
                "message": f"{event_base['type']} detected on {target_node}"
            }
            yield event
            time.sleep(5)
