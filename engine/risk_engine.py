class RiskEngine:
    @staticmethod
    def calculate_risk(path, graph):
        """
        Risk = Exposure*0.4 + Privilege*0.35 + Connectivity*0.25
        """
        exposure = 0
        privilege = 0
        connectivity = 1 / len(path) if len(path) > 0 else 0

        for node in path:
            data = graph.nodes[node]
            if data.get('is_public'):
                exposure = 1.0
            if data.get('is_admin'):
                privilege = 1.0

        score = (exposure * 0.4 + privilege * 0.35 + connectivity * 0.25) * 100
        
        severity = "LOW"
        if score > 70:
            severity = "HIGH"
        elif score > 40:
            severity = "MEDIUM"
            
        return {
            "score": round(score, 2),
            "severity": severity
        }

    @staticmethod
    def calculate_risk_summary(graph, paths):
        """
        Calculates a high-level risk summary for the entire infrastructure.
        """
        all_scores = []
        top_issues = []
        
        # Calculate scores for all discovered paths
        for p_info in paths:
            path = p_info['path']
            r = RiskEngine.calculate_risk(path, graph)
            all_scores.append(r['score'])
            
            # Identify top issues from the path nodes
            for node_id in path:
                if node_id == "Internet": continue
                node_data = graph.nodes[node_id]
                
                issue = None
                risk_lvl = "LOW"
                
                if node_data.get('is_public'):
                    issue = f"Publicly exposed {node_data.get('type')}"
                    risk_lvl = "HIGH"
                elif node_data.get('is_admin'):
                    issue = "Administrative privileges detected"
                    risk_lvl = "HIGH"
                
                if issue:
                    issue_entry = {
                        "type": node_data.get('type', 'Resource'),
                        "resource": node_id,
                        "issue": issue,
                        "risk": risk_lvl
                    }
                    if issue_entry not in top_issues:
                        top_issues.append(issue_entry)

        max_score = max(all_scores) if all_scores else 0
        
        # Determine Status
        status = "LOW"
        if max_score > 70: status = "HIGH"
        elif max_score > 30: status = "MEDIUM"
        
        # Breakdown metrics
        public_count = len([n for n, d in graph.nodes(data=True) if d.get('is_public')])
        admin_count = len([n for n, d in graph.nodes(data=True) if d.get('is_admin')])
        
        # Misconfigurations (simplified: count risky nodes)
        misconfig_count = len([n for n, d in graph.nodes(data=True) if d.get('is_public') or d.get('is_admin')])

        # Attack Surface
        public_nodes = public_count
        private_nodes = graph.number_of_nodes() - public_nodes - 1 # -1 for Internet node
        
        return {
            "total_score": round(max_score, 0),
            "status": status,
            "breakdown": {
                "public_exposure": public_count,
                "admin_privileges": admin_count,
                "misconfigurations": misconfig_count
            },
            "top_issues": top_issues[:5], # Limit to top 5
            "attack_surface": {
                "public_nodes": public_nodes,
                "private_nodes": max(0, private_nodes)
            }
        }
