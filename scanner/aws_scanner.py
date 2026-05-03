import boto3
from botocore.exceptions import ClientError

class AWSScanner:
    def __init__(self, access_key=None, secret_key=None, region='us-east-1'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.session = self._create_session()

    def _create_session(self):
        try:
            if self.access_key and self.secret_key:
                session = boto3.Session(
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    region_name=self.region
                )
            else:
                # Use default local credentials if not provided (for local dev)
                session = boto3.Session(region_name=self.region)
            
            # Validate credentials using STS
            sts = session.client('sts')
            sts.get_caller_identity()
            return session
        except Exception as e:
            raise Exception(f"AWS Authentication Failed: {str(e)}")

    def scan_ec2(self):
        ec2 = self.session.client('ec2')
        instances = []
        try:
            paginator = ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instances.append({
                            'id': instance['InstanceId'],
                            'public_ip': instance.get('PublicIpAddress'),
                            'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                            'iam_role': instance.get('IamInstanceProfile', {}).get('Arn'),
                            'state': instance['State']['Name']
                        })
        except ClientError as e:
            print(f"Error scanning EC2: {e}")
        return instances

    def scan_iam(self):
        iam = self.session.client('iam')
        roles = []
        try:
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    # Simple admin check: Check if AdministratorAccess is attached
                    is_admin = False
                    try:
                        attached_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
                        is_admin = any(p['PolicyName'] == 'AdministratorAccess' for p in attached_policies.get('AttachedPolicies', []))
                    except: pass
                    
                    roles.append({
                        'arn': role['Arn'],
                        'name': role['RoleName'],
                        'admin': is_admin
                    })
        except ClientError as e:
            print(f"Error scanning IAM: {e}")
        return roles

    def scan_s3(self):
        s3 = self.session.client('s3')
        buckets = []
        try:
            response = s3.list_buckets()
            for bucket in response['Buckets']:
                # Check for public access
                public = False
                try:
                    policy_status = s3.get_public_access_block(Bucket=bucket['Name'])
                    # If all blocks are false, we'll consider it potentially public for this tool's logic
                    conf = policy_status['PublicAccessBlockConfiguration']
                    public = not all([conf['BlockPublicAcls'], conf['IgnorePublicAcls'], conf['BlockPublicPolicy'], conf['RestrictPublicBuckets']])
                except:
                    public = True # Default to public if no block config exists
                
                buckets.append({
                    'name': bucket['Name'],
                    'public': public
                })
        except ClientError as e:
            print(f"Error scanning S3: {e}")
        return buckets

    def scan_security_groups(self):
        ec2 = self.session.client('ec2')
        sgs = []
        try:
            response = ec2.describe_security_groups()
            for sg in response['SecurityGroups']:
                open_to_world = False
                for permission in sg.get('IpPermissions', []):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            open_to_world = True
                            break
                sgs.append({
                    'id': sg['GroupId'],
                    'open_to_world': open_to_world
                })
        except ClientError as e:
            print(f"Error scanning Security Groups: {e}")
        return sgs

    def run_full_scan(self):
        return {
            'ec2': self.scan_ec2(),
            'iam': self.scan_iam(),
            's3': self.scan_s3(),
            'security_groups': self.scan_security_groups()
        }
