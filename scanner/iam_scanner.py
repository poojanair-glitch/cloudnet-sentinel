import boto3
from botocore.exceptions import ClientError

def scan_iam(session):
    """
    Scans IAM users and roles to detect administrative privileges.
    """
    iam = session.client('iam')
    identities = []
    
    try:
        # Scan Users
        users_response = iam.list_users()
        for user in users_response['Users']:
            user_name = user['UserName']
            is_admin = False
            
            # Check attached policies
            policies = iam.list_attached_user_policies(UserName=user_name)
            for policy in policies['AttachedPolicies']:
                if 'AdministratorAccess' in policy['PolicyName']:
                    is_admin = True
            
            identities.append({
                'id': user['Arn'],
                'name': user_name,
                'type': 'IAM_USER',
                'is_admin': is_admin
            })

        # Scan Roles (Simplified for logic)
        roles_response = iam.list_roles()
        for role in roles_response['Roles']:
            role_name = role['RoleName']
            
            # Filter out AWS Service Roles
            if role_name.startswith('AWSServiceRole'):
                continue
                
            is_admin = False
            
            policies = iam.list_attached_role_policies(RoleName=role_name)
            for policy in policies['AttachedPolicies']:
                if 'AdministratorAccess' in policy['PolicyName']:
                    is_admin = True
            
            identities.append({
                'id': role['Arn'],
                'name': role_name,
                'type': 'IAM_ROLE',
                'is_admin': is_admin
            })

    except ClientError as e:
        print(f"Error scanning IAM: {e}")
    
    return identities
