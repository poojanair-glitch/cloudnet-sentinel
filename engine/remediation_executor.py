import boto3
import logging

class RemediationExecutor:
    def __init__(self, region='us-east-1', dry_run=True):
        self.ec2 = boto3.client('ec2', region_name=region)
        self.iam = boto3.client('iam')
        self.dry_run = dry_run
        
        # Configure Logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - SentinelRemediator - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def execute(self, suggestions):
        results = []
        for s in suggestions:
            action = s.get('action')
            resource_id = s.get('resource_id')
            params = s.get('params', {})
            
            self.logger.info(f"Evaluating action: {action} on {resource_id} (Dry Run: {self.dry_run})")
            
            result = {'id': s['id'], 'status': 'SKIPPED', 'message': ''}
            
            try:
                if action == 'revoke_sg_ingress':
                    result = self._revoke_sg_ingress(resource_id, params)
                elif action == 'detach_admin_policy':
                    result = self._detach_admin_policy(resource_id, params)
                else:
                    result['message'] = "Unknown action type"
            except Exception as e:
                self.logger.error(f"Failed to execute {action} on {resource_id}: {str(e)}")
                result['status'] = 'FAILED'
                result['message'] = str(e)
            
            results.append(result)
        return results

    def _revoke_sg_ingress(self, instance_id, params):
        if self.dry_run:
            return {'status': 'DRY_RUN_SUCCESS', 'message': f"Would revoke {params['cidr']} for instance {instance_id}"}
        
        # In reality, we find SGs attached to the instance and revoke 0.0.0.0/0
        # For simplicity in this CLI implementation:
        try:
            res = self.ec2.describe_instances(InstanceIds=[instance_id])
            sgs = [sg['GroupId'] for sg in res['Reservations'][0]['Instances'][0]['SecurityGroups']]
            
            for sg_id in sgs:
                self.logger.info(f"Revoking global ingress for SG {sg_id}")
                self.ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    CidrIp=params['cidr'],
                    IpProtocol='-1' # All traffic
                )
            return {'status': 'SUCCESS', 'message': f"Revoked global access for {instance_id}"}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}

    def _detach_admin_policy(self, role_arn, params):
        role_name = role_arn.split('/')[-1]
        if self.dry_run:
            return {'status': 'DRY_RUN_SUCCESS', 'message': f"Would detach {params['policy_arn']} from role {role_name}"}
        
        try:
            self.iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn=params['policy_arn']
            )
            return {'status': 'SUCCESS', 'message': f"Detached Admin policy from {role_name}"}
        except Exception as e:
            return {'status': 'FAILED', 'message': str(e)}
