import boto3
from botocore.exceptions import ClientError

def scan_s3(session):
    """
    Scans S3 buckets and identifies public access.
    """
    s3 = session.client('s3')
    buckets = []
    
    try:
        response = s3.list_buckets()
        for bucket in response['Buckets']:
            name = bucket['Name']
            is_public = False
            
            try:
                # Check Public Access Block
                pab = s3.get_public_access_block(Bucket=name)
                config = pab['PublicAccessBlockConfiguration']
                if not all([config['BlockPublicAcls'], config['IgnorePublicAcls'], 
                            config['BlockPublicPolicy'], config['RestrictPublicBuckets']]):
                    is_public = True
            except ClientError:
                # If no PAB config, might be public
                is_public = True
                
            buckets.append({
                'id': name,
                'type': 'S3',
                'is_public': is_public
            })
    except ClientError as e:
        print(f"Error scanning S3: {e}")
        
    return buckets
