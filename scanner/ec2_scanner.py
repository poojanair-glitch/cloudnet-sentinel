import boto3
from botocore.exceptions import ClientError

def scan_ec2(session):
    """
    Scans EC2 instances and identifies public exposure via Public IP and Security Groups.
    """
    ec2 = session.client('ec2')
    instances = []
    try:
        response = ec2.describe_instances()
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'running':
                    instance_id = instance['InstanceId']
                    public_ip = instance.get('PublicIpAddress')
                    security_groups = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    vpc_id = instance.get('VpcId')
                    subnet_id = instance.get('SubnetId')
                    iam_profile = instance.get('IamInstanceProfile', {}).get('Arn')
                    
                    # Logic: If it has a public IP, consider it potentially exposed
                    instances.append({
                        'id': instance_id,
                        'type': 'EC2',
                        'public_ip': public_ip,
                        'security_groups': security_groups,
                        'vpc_id': vpc_id,
                        'subnet_id': subnet_id,
                        'iam_profile_arn': iam_profile,
                        'is_public': public_ip is not None
                    })
    except ClientError as e:
        print(f"Error scanning EC2: {e}")
    return instances
