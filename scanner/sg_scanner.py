import boto3
from botocore.exceptions import ClientError

def scan_security_groups(session):
    """
    Scans security groups for permissive rules.
    """
    ec2 = session.client('ec2')
    sgs = []
    
    try:
        response = ec2.describe_security_groups()
        for sg in response['SecurityGroups']:
            is_open = False
            for permission in sg.get('IpPermissions', []):
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        is_open = True
            
            sgs.append({
                'id': sg['GroupId'],
                'name': sg['GroupName'],
                'is_open': is_open
            })
    except ClientError as e:
        print(f"Error scanning SG: {e}")
        
    return sgs
