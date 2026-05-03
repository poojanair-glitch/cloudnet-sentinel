import networkx as nx

class GraphBuilder:
    def __init__(self, scan_data):
        self.data = scan_data
        self.G = nx.DiGraph()

    def build(self):
        # 1. Add Entry Point
        self.G.add_node("Internet", type="external", label="🌐 Internet")

        # 2. Add EC2 Nodes and Internet -> EC2 edges
        sgs = {sg['id']: sg for sg in self.data.get('security_groups', [])}
        for ec2 in self.data.get('ec2', []):
            is_public = ec2.get('public_ip') is not None
            open_ports = False
            for sg_id in ec2.get('security_groups', []):
                if sgs.get(sg_id, {}).get('open_to_world'):
                    open_ports = True
                    break
            
            node_id = ec2['id']
            self.G.add_node(node_id, 
                            type="ec2", 
                            label=f"🖥️ {node_id}", 
                            public=is_public, 
                            open_ports=open_ports,
                            evidence=f"Public: {is_public}, Open SG: {open_ports}")
            
            if is_public and open_ports:
                self.G.add_edge("Internet", node_id, type="exposure", reason="Public IP + Open Security Group")

        # 3. Add IAM Nodes and EC2 -> IAM edges
        iam_roles = {role['arn']: role for role in self.data.get('iam', [])}
        for ec2 in self.data.get('ec2', []):
            role_arn = ec2.get('iam_role')
            if role_arn:
                role_data = iam_roles.get(role_arn, {'name': role_arn.split('/')[-1], 'admin': False})
                self.G.add_node(role_arn, 
                                type="iam", 
                                label=f"🔐 {role_data['name']}", 
                                admin=role_data.get('admin', False),
                                evidence=f"Admin: {role_data.get('admin', False)}")
                self.G.add_edge(ec2['id'], role_arn, type="permission", reason="Instance Profile Role")

        # 4. Add S3 Nodes and IAM -> S3 edges
        for s3 in self.data.get('s3', []):
            node_id = s3['name']
            self.G.add_node(node_id, 
                            type="s3", 
                            label=f"🪣 {node_id}", 
                            public=s3.get('public', False),
                            evidence=f"Public: {s3.get('public', False)}")
            
            # Link IAM to S3 if IAM is admin (simulated logic per requirements)
            for role_arn in iam_roles:
                if iam_roles[role_arn].get('admin'):
                    self.G.add_edge(role_arn, node_id, type="data_access", reason="Admin role has full access")

        return self.G
