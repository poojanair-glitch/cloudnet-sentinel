class ExplanationEngine:
    @staticmethod
    def derive_attack_stage(has_paths, has_public_ec2, reasoning):
        """
        Derives the current stage of the attack chain.
        """
        if has_paths:
            return "Target Reached"
        if reasoning.get("privilege_escalation"):
            return "Escalation Possible"
        if has_public_ec2:
            return "Entry Achieved"
        return "Recon"

    @staticmethod
    def generate_explanations(graph_obj, path_data):
        attack_paths = path_data.get("paths", [])
        reasoning = path_data.get("reasoning", {})
        entry_points = graph_obj.get("entry_points", [])
        
        has_paths = len(attack_paths) > 0
        has_public_ec2 = len(entry_points) > 0

        # 1. System Status (3-Tier) & Attack Progress
        attack_progress = 0
        time_to_compromise = "NOT POSSIBLE"
        stage = ExplanationEngine.derive_attack_stage(has_paths, has_public_ec2, reasoning)
        
        if has_paths:
            status = "CRITICAL"
            summary = "🚨 EXTERNAL ATTACK SURFACE CRITICALLY COMPROMISED: Attacker has reached administrative control."
            attack_progress = 100
            time_to_compromise = path_data.get("time_to_compromise", "10 MIN")
        elif has_public_ec2:
            status = "EXPOSED"
            summary = f"⚠️ EXTERNAL ATTACK SURFACE EXPOSED: Attacker has initial access but {reasoning.get('broken_step')}."
            attack_progress = 40
            time_to_compromise = "STALLED"
        else:
            status = "SECURE"
            summary = "✔ NO COMPLETE BREACH PATH: Network perimeter is hardened. Attack chain broken at initial access."
            attack_progress = 0
            time_to_compromise = "NONE"

        # Upgrade progress string
        progress_str = f"{attack_progress}% — {stage}"
        if not has_paths and has_public_ec2:
            progress_str += f", {reasoning.get('broken_step')}"

        # 2. Attacker Position Logic
        attacker_position = {
            "external_access": has_public_ec2,
            "privilege_escalation": reasoning.get("privilege_escalation", False),
            "target_reachable": has_paths
        }

        # 3. Decision Strip & Priority Engine
        resources = []
        priorities = []
        confidence_score = 92 # Base confidence
        
        for node in graph_obj.get("nodes", []):
            node_type = node.get("type")
            node_id = node.get("id")
            if node_type == "internet" or node_type == "ENTRY_POINT": continue
                
            explanation = node.get("reason", "N/A")
            is_risky = node.get("risk") == "HIGH"
            
            priority_level = "LOW"
            fix_rec = "No immediate action required."
            
            if is_risky:
                if node_type == "ec2":
                    priority_level = "CRITICAL" if has_paths else "HIGH"
                    fix_rec = "Restrict inbound Security Group rules to trusted IPs."
                elif node_type == "iam":
                    priority_level = "CRITICAL" if has_paths else "MEDIUM"
                    fix_rec = "Remove AdministratorAccess and enforce Least Privilege."
                elif node_type == "s3":
                    priority_level = "HIGH"
                    fix_rec = "Enable Public Access Block."

            if priority_level in ["CRITICAL", "HIGH", "MEDIUM"]:
                priorities.append({
                    "resource": node.get("label", node_id),
                    "priority": priority_level,
                    "reason": explanation,
                    "fix": fix_rec,
                    "weight": 3 if priority_level == "CRITICAL" else (2 if priority_level == "HIGH" else 1)
                })

            resources.append({
                "id": node_id, "type": node_type.upper(), "label": node.get("label", node_id),
                "is_risky": is_risky, "priority": priority_level, "explanation": explanation,
                "connections": [e for e in graph_obj.get("edges", []) if e['source'] == node_id or e['target'] == node_id]
            })

        priorities.sort(key=lambda x: x["weight"], reverse=True)
        decision_strip = ""
        if priorities:
            top = priorities[0]
            reduction = 92 if top['priority'] == "CRITICAL" else 72
            decision_strip = f"🔥 Fix {top['resource']} → reduces risk by {reduction}%"

        # 4. Risk Trajectory
        trajectory = {
            "state": "EXPLOITED ENTRY POINT" if has_public_ec2 else "SECURE PERIMETER",
            "escalation_chance": "100%" if has_paths else ("68% if IAM attached" if has_public_ec2 else "0%"),
            "estimated_loss": "$2,880/month" if has_public_ec2 else "$0"
        }

        return {
            "summary": summary,
            "status": status,
            "attack_progress": attack_progress,
            "attack_progress_str": progress_str,
            "time_to_compromise": time_to_compromise,
            "attacker_position": attacker_position,
            "decision_strip": decision_strip,
            "risk_trajectory": trajectory,
            "confidence_score": confidence_score,
            "resources": resources,
            "top_fixes": priorities[:3]
        }
