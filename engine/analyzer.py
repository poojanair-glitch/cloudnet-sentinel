import networkx as nx

class AttackTechnique:
    LATERAL_MOVEMENT = "T1210 - Exploitation of Remote Services"
    PRIVILEGE_ESCALATION = "T1548 - Abuse Elevation Control Mechanism"
    DATA_EXFILTRATION = "T1537 - Transfer Data to Cloud Account"
    INITIAL_ACCESS = "T1190 - Valid Accounts"

class AttackPathAnalyzer:
    def __init__(self, G):
        self.G = G

    def find_paths(self, max_depth=7):
        findings = []
        
        # 1. Identify Entry Points (Sources)
        sources = [n for n, d in self.G.nodes(data=True) if d.get('type') == 'external' or (d.get('type') == 'ec2' and d.get('public'))]
        if not sources:
            sources = ["Internet"] # Fallback

        # 2. Identify Sensitive Targets
        targets = [n for n, d in self.G.nodes(data=True) if d.get('type') == 's3' or (d.get('type') == 'iam' and d.get('admin'))]

        # 3. Detect Direct Exposures
        for n, d in self.G.nodes(data=True):
            if d.get('type') == 'ec2' and d.get('evidence'):
                exposed_ports = [e for e in d.get('evidence', []) if "Port" in e]
                if exposed_ports:
                    findings.append({
                        'type': 'Scenario: External Access',
                        'path': ['Internet', n],
                        'severity': 'HIGH',
                        'evidence': [
                            {'id': 'Internet', 'type': 'external', 'settings': ['🌐 External Gateway']},
                            {'id': n, 'type': 'ec2', 'settings': d.get('evidence')}
                        ],
                        'hops': 1,
                        'mitre_techniques': [AttackTechnique.INITIAL_ACCESS],
                        'description': f"Direct External Access detected: Instance {n} is exposed via {', '.join(exposed_ports)}."
                    })

        # 4. Scenario-Based Traversal
        for source in sources:
            for target in targets:
                if source == target: continue
                
                try:
                    paths = nx.all_simple_paths(self.G, source=source, target=target, cutoff=max_depth)
                    
                    for p in paths:
                        evidence_chain = []
                        mitre_techniques = set()
                        scenario = "Multi-Step Attack Path"
                        
                        # Identify Scenarios
                        has_ec2 = any(self.G.nodes[node].get('type') == 'ec2' for node in p)
                        has_iam = any(self.G.nodes[node].get('type') == 'iam' for node in p)
                        has_s3 = any(self.G.nodes[node].get('type') == 's3' for node in p)

                        if has_ec2 and not has_iam and not has_s3:
                            scenario = "Scenario: External Access"
                        elif has_ec2 and has_iam and not has_s3:
                            scenario = "Scenario: Privilege Escalation"
                        elif has_iam and has_s3:
                            scenario = "Scenario: Data Exfiltration"

                        for i in range(len(p)):
                            node = p[i]
                            node_data = self.G.nodes[node]
                            evidence_chain.append({
                                'id': node,
                                'type': node_data.get('type'),
                                'settings': node_data.get('evidence', []),
                                'label': node_data.get('name', node)
                            })
                            
                            if i > 0:
                                edge_data = self.G.get_edge_data(p[i-1], p[i])
                                edge_type = edge_data.get('type', '')
                                if edge_type == 'sts_assume': 
                                    mitre_techniques.add(AttackTechnique.PRIVILEGE_ESCALATION)
                                elif edge_type == 'lateral_movement': 
                                    mitre_techniques.add(AttackTechnique.LATERAL_MOVEMENT)
                                elif edge_type == 'data_access': 
                                    mitre_techniques.add(AttackTechnique.DATA_EXFILTRATION)
                                elif edge_type in ['network_exposure', 'iam_assume']:
                                    mitre_techniques.add(AttackTechnique.INITIAL_ACCESS)

                        severity = "CRITICAL" if self.G.nodes[target].get('admin') or self.G.nodes[target].get('type') == 's3' else "HIGH"
                        
                        findings.append({
                            'type': scenario,
                            'path': p,
                            'evidence': evidence_chain,
                            'severity': severity,
                            'hops': len(p) - 1,
                            'mitre_techniques': list(mitre_techniques),
                            'description': f"Chained {scenario} detected involving {len(p)} nodes. Target: {target}."
                        })
                except nx.NetworkXNoPath:
                    continue
                except Exception:
                    continue

        return findings

class RiskEngine:
    def __init__(self, history_file='data/risk_history.json'):
        self.history_file = history_file

    def calculate_score(self, findings, graph):
        if not findings: return 12, "LOW", 0, []
        
        total_risk = 0
        risk_factors = []
        
        # Track factors to avoid duplicates in the explanation
        has_admin = False
        has_s3 = False
        has_public_ec2 = False

        for f in findings:
            target_node = f['path'][-1]
            target_data = graph.nodes[target_node]
            
            # 1. Base Severity
            if target_data.get('admin') or target_data.get('type') == 'iam' and target_data.get('admin'):
                base_severity = 7.0
                has_admin = True
            elif target_data.get('type') == 's3':
                base_severity = 7.0
                has_s3 = True
            elif target_data.get('type') == 'ec2':
                evidence_str = str(target_data.get('evidence', []))
                if 'Port 22' in evidence_str or 'Port 3389' in evidence_str or 'Port ALL' in evidence_str:
                    base_severity = 8.0
                    has_public_ec2 = True
                else:
                    base_severity = 4.0
            else:
                base_severity = 4.0
            
            sensitivity = target_data.get('sensitivity', 1.0)
            hops = f.get('hops', 1)
            path_multiplier = max(0.5, 2.0 - (hops * 0.2))
            exposure = 1.5 if any(ev['type'] == 'ec2' and ev.get('settings') for ev in f['evidence']) else 1.0
            
            path_risk = base_severity * sensitivity * path_multiplier * exposure
            total_risk += path_risk

        # Build Explainable Factors
        if has_admin: risk_factors.append("Identity Over-Privilege: Admin roles reachable from public endpoints.")
        if has_s3: risk_factors.append("Data Exposure: Sensitive S3 buckets found on multi-hop paths.")
        if has_public_ec2: risk_factors.append("Network Exposure: Management ports (SSH/RDP) open to the world.")
        if len(findings) > 5: risk_factors.append("High Attack Surface: Large number of potential breach vectors detected.")

        # Normalize to 0-100
        final_score = min(total_risk * 2, 100)
        
        severity = "LOW"
        if final_score > 85: severity = "CRITICAL"
        elif final_score > 65: severity = "HIGH"
        elif final_score > 40: severity = "MEDIUM"
        
        drift = self._detect_drift(final_score)
        
        return round(final_score, 2), severity, drift, risk_factors


    def _detect_drift(self, current_score):
        try:
            import json
            import os
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
                last_score = history[-1]['score']
                return round(current_score - last_score, 2)
        except: pass
        return 0

    def save_history(self, score):
        try:
            import json
            import os
            import datetime
            history = []
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            
            history.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'score': score
            })
            
            # Keep last 50 entries
            history = history[-50:]
            
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=4)
        except: pass

class CostEngine:
    def analyze_impact(self, risk_score, billing_data):
        """
        Estimate financial impact of a potential breach.
        Factors: Data Exfiltration, Ransomware, Incident Response, and Regulatory Fines.
        """
        monthly_spend = billing_data.get('est_monthly_spend', 0)
        # Convert USD to INR (Approx 1 USD = 83 INR)
        monthly_spend_inr = monthly_spend * 83
        
        # 1. Data Exfiltration Cost (Scale with risk score and infra size)
        exfiltration_cost = (risk_score / 100) * (monthly_spend_inr * 2) + 50000
        
        # 2. Ransomware / Downtime (10x of daily spend for recovery period)
        daily_spend_inr = billing_data.get('avg_daily_spend', 0) * 83
        downtime_cost = (risk_score / 100) * (daily_spend_inr * 15)
        
        # 3. Incident Response & Forensics (Base cost + scale with complexity)
        ir_cost = 250000 + (risk_score * 5000)
        
        # 4. Regulatory Fines (e.g., GDPR/DPDP - fixed base if risk is high)
        legal_cost = 500000 if risk_score > 70 else 100000
        
        total_impact = exfiltration_cost + downtime_cost + ir_cost + legal_cost
        
        return {
            'total': round(total_impact, 2),
            'currency': 'INR',
            'breakdown': [
                {'item': 'Data Exfiltration', 'cost': round(exfiltration_cost, 2), 'reason': 'Estimated value of compromised data assets.'},
                {'item': 'Recovery & Downtime', 'cost': round(downtime_cost, 2), 'reason': 'Business interruption and system restoration.'},
                {'item': 'Forensics & IR', 'cost': round(ir_cost, 2), 'reason': 'Professional services for breach investigation.'},
                {'item': 'Legal & Compliance', 'cost': round(legal_cost, 2), 'reason': 'Regulatory fines and legal counsel.'}
            ],
            'infrastructure_value': f"₹{round(monthly_spend_inr, 2)} (Monthly AWS Spend)"
        }

class RemediationEngine:
    def get_suggestions(self, findings):
        suggestions = []
        seen_actions = set()
        
        for f in findings:
            for ev in f['evidence']:
                ev_id = ev.get('id', 'unknown')
                settings_str = str(ev.get('settings', []))
                
                if ev['type'] == 'ec2' and ev.get('settings'):
                    action_key = f"fix_sg_{ev_id}"
                    if action_key not in seen_actions:
                        if 'Port 22' in settings_str:
                            suggestions.append({
                                'id': action_key,
                                'title': "Restrict SSH Access (Port 22)",
                                'description': f"Instance {ev_id} has SSH open to 0.0.0.0/0. Limit access to your office IP.",
                                'icon': '🛡️',
                                'action': 'revoke_sg_ingress',
                                'resource_id': ev_id,
                                'params': {'port': 22, 'cidr': '0.0.0.0/0'}
                            })
                        else:
                            suggestions.append({
                                'id': action_key,
                                'title': "Tighten Security Group Rules",
                                'description': f"Instance {ev_id} is publicly exposed. Revoke 0.0.0.0/0 access.",
                                'icon': '🛡️',
                                'action': 'revoke_sg_ingress',
                                'resource_id': ev_id,
                                'params': {'cidr': '0.0.0.0/0'}
                            })
                        seen_actions.add(action_key)
                
                if ev['type'] == 'iam' and ('AdministratorAccess' in settings_str or ev.get('admin')):
                    action_key = f"fix_iam_{ev_id}"
                    if action_key not in seen_actions:
                        suggestions.append({
                            'id': action_key,
                            'title': "Implement Least Privilege for IAM",
                            'description': f"Role {ev_id} has Administrative privileges. Detach AdministratorAccess.",
                            'icon': '🔐',
                            'action': 'detach_admin_policy',
                            'resource_id': ev_id,
                            'params': {'policy_arn': 'arn:aws:iam::aws:policy/AdministratorAccess'}
                        })
                        seen_actions.add(action_key)
        
        return suggestions

class Visualizer:
    @staticmethod
    def export_graph_json(G, paths):
        """
        Exports the NetworkX graph to a D3.js compatible JSON format.
        Highlights nodes and edges that are part of any attack path.
        """
        # Identify all nodes and edges in attack paths
        path_nodes = set()
        path_edges = set()
        for p in paths:
            nodes = p['path']
            for node in nodes:
                path_nodes.add(node)
            for i in range(len(nodes) - 1):
                path_edges.add((nodes[i], nodes[i+1]))

        nodes_data = []
        for n, d in G.nodes(data=True):
            nodes_data.append({
                "id": n,
                "type": d.get('type', 'unknown'),
                "icon": d.get('icon', '❓'),
                "label": d.get('name', n),
                "is_compromised": n in path_nodes,
                "sensitivity": d.get('sensitivity', 1.0)
            })

        links_data = []
        for u, v, d in G.edges(data=True):
            links_data.append({
                "source": u,
                "target": v,
                "type": d.get('type', 'link'),
                "label": d.get('label', ''),
                "is_attack_path": (u, v) in path_edges
            })

        return {
            "nodes": nodes_data,
            "links": links_data
        }
