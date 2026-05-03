class CorrelationEngine:
    def __init__(self, attack_paths):
        self.attack_paths = attack_paths

    def correlate(self, event):
        """
        If event affects a node in an attack path -> mark as ACTIVE ATTACK
        """
        involved_paths = []
        for ap in self.attack_paths:
            if event['node'] in ap:
                involved_paths.append(ap)
        
        impact_type = "No Significant Impact"
        if involved_paths:
            # Check if it's entry node
            if any(p[0] == event['node'] for p in involved_paths):
                impact_type = "Affects Entry Node"
            elif any(event['node'] in p[1:-1] for p in involved_paths):
                impact_type = "Increases Escalation Probability"
            elif any(p[-1] == event['node'] for p in involved_paths):
                impact_type = "Expands Blast Radius"

            return {
                "status": "ACTIVE ATTACK",
                "event": event,
                "impacted_paths": involved_paths,
                "impact_type": impact_type,
                "impact_message": f"This event increases attack feasibility by {len(involved_paths) * 15}%"
            }
        
        return {
            "status": "NORMAL",
            "event": event,
            "impact_type": impact_type,
            "impact_message": "No significant impact on known attack paths."
        }
