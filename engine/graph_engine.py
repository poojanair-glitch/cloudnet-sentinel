import networkx as nx

class GraphEngine:
    def __init__(self):
        self.G = nx.DiGraph()

    def build_graph(self, scan_data, simulation_flags=None):
        self.G.clear()
        
        # 1. Add Entry Point
        self.G.add_node("Internet", type="internet", public=True, risk="EXTERNAL", label="External Entry Point")

        subnets = {s['SubnetId']: s for s in scan_data.get('subnets', [])}
        open_sgs = {sg['id'] for sg in scan_data.get('sgs', []) if sg.get('is_open')}
        iam_map = {i['id']: i for i in scan_data.get('iam', [])}
        s3_list = scan_data.get('s3', [])
        vpcs = {v['VpcId']: v for v in scan_data.get('vpcs', [])}

        # 2. VPCs
        for vpc_id, vpc in vpcs.items():
            self.G.add_node(
                vpc_id,
                type="vpc",
                risk="LOW",
                label=f"VPC: {vpc_id}",
                reason="Structural Network Container"
            )

        # 3. Subnets
        for subnet_id, subnet in subnets.items():
            is_pub = subnet.get('MapPublicIpOnLaunch', False)
            self.G.add_node(
                subnet_id,
                type="subnet",
                public=is_pub,
                risk="MEDIUM" if is_pub else "LOW",
                label=f"Subnet: {subnet_id} {'(Public)' if is_pub else ''}",
                reason="Public Subnet (Auto-assign IP)" if is_pub else "Private Subnet"
            )
            vpc_id = subnet.get('VpcId')
            if vpc_id in self.G:
                self.G.add_edge(vpc_id, subnet_id, relation="contains", label="Contains", color="grey")

        # 4. EC2
        ec2_nodes = []
        entry_points = []
        for ec2 in scan_data.get('ec2', []):
            if ec2.get('state') and ec2.get('state') != 'running':
                continue

            subnet_id = ec2.get('subnet_id')
            subnet_data = subnets.get(subnet_id, {})
            is_public_subnet = subnet_data.get('MapPublicIpOnLaunch', False)
            
            is_exposed = self.is_public_ec2(ec2, is_public_subnet, open_sgs)
            risk_level = "HIGH" if is_exposed else "LOW"
            
            self.G.add_node(
                ec2['id'], 
                type="ec2", 
                public=is_exposed, 
                risk=risk_level, 
                label=f"{ec2['id']} {'(Public)' if is_exposed else '(Private)'}",
                reason="Public IP + Open SG + Public Subnet" if is_exposed else "No direct internet access",
                data=ec2
            )
            
            if is_exposed:
                self.G.add_edge("Internet", ec2['id'], relation="exposed", label="Public Access", color="orange")
                entry_points.append(ec2['id'])
            
            # Link EC2 to Subnet
            if subnet_id in self.G:
                self.G.add_edge(subnet_id, ec2['id'], relation="hosts", label="Hosts", color="grey")
            
            ec2_nodes.append(ec2)

        # 5. IAM
        privileged_nodes = []
        for ec2 in ec2_nodes:
            profile_arn = ec2.get('iam_profile_arn')
            
            # SIMULATION: If 'simulate_iam' is True, and this instance has NO role, we simulate attaching an admin role
            if not profile_arn and simulation_flags and simulation_flags.get('simulate_iam'):
                # Pick first admin role from scan data or create mock
                admin_roles = [r for r in iam_map.values() if r.get('is_admin')]
                if admin_roles:
                    profile_arn = admin_roles[0]['id']

            if not profile_arn:
                continue

            for iam_id, iam in iam_map.items():
                if iam['name'] in profile_arn or iam_id == profile_arn:
                    is_admin = iam.get('is_admin')
                    risk_level = "HIGH" if is_admin else "LOW"
                    
                    if iam_id not in self.G:
                        self.G.add_node(
                            iam_id, 
                            type="iam", 
                            public=False, 
                            risk=risk_level, 
                            label=f"{iam['name']} {'(Admin)' if is_admin else ''}",
                            is_admin=is_admin,
                            reason="AdministratorAccess policy attached" if is_admin else "Limited permissions"
                        )
                        if is_admin:
                            privileged_nodes.append(iam_id)
                    
                    self.G.add_edge(ec2['id'], iam_id, relation="assume_role", label="Assumes Role", color="grey")

        # 4. S3
        for iam_id, iam in iam_map.items():
            if iam_id not in self.G:
                continue 
            
            for s3 in s3_list:
                if self.has_s3_access(iam) and s3.get('is_public'):
                    risk_level = "HIGH"
                    
                    if s3['id'] not in self.G:
                        self.G.add_node(
                            s3['id'], 
                            type="s3", 
                            public=True, 
                            risk=risk_level, 
                            label=f"{s3['id']} (Public Bucket)",
                            reason="Public Access Block Disabled"
                        )
                    
                    self.G.add_edge(iam_id, s3['id'], relation="data_access", label="S3 Data Access", color="grey")

        return {
            "graph": self.G,
            "nodes": [{"id": n, **d} for n, d in self.G.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in self.G.edges(data=True)],
            "entry_points": entry_points,
            "privileged_nodes": privileged_nodes
        }

    def is_public_ec2(self, ec2, is_public_subnet, open_sgs):
        has_public_ip = ec2.get('public_ip') is not None
        has_open_sg = any(sg in open_sgs for sg in ec2.get('security_groups', []))
        return has_public_ip and is_public_subnet and has_open_sg

    def has_s3_access(self, iam):
        return iam.get('is_admin', False)
