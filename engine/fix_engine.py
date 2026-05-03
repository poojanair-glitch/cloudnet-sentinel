class FixEngine:
    @staticmethod
    def get_recommendations(path, graph):
        fixes = []
        for node in path:
            data = graph.nodes.get(node, {})
            ntype = data.get('type')
            
            if ntype == 'EC2' and data.get('is_public'):
                fixes.append({
                    "resource": node,
                    "fix": "Restrict Security Group to known IPs only (remove 0.0.0.0/0)."
                })
            elif ntype in ['IAM_USER', 'IAM_ROLE'] and data.get('is_admin'):
                fixes.append({
                    "resource": node,
                    "fix": "Remove AdministratorAccess. Apply Least Privilege principle using specific service permissions."
                })
            elif ntype == 'S3' and data.get('is_public'):
                fixes.append({
                    "resource": node,
                    "fix": "Enable 'Block Public Access' at the bucket level and check bucket policies."
                })
        return fixes
