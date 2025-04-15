import boto3 # type: ignore
from app import app

waf_client = boto3.client('waf-regional', region_name=app.config['AWS_REGION'])

def create_waf_rule():
    response = waf_client.create_rule(
        Name='MaliciousRequestRule',
        MetricName='MaliciousRequestRule',
        ChangeToken=waf_client.get_change_token()['ChangeToken'],
        Predicates=[
            {
                'DataId': 'IPSet-ID',  # Replace with your actual IPSet ID
                'Negated': False,
                'Type': 'IPMatch'
            }
        ]
    )
    return response['Rule']['RuleId']

def update_ip_set(ip_address, ip_set_id='IPSet-ID'):
    change_token = waf_client.get_change_token()['ChangeToken']
    waf_client.update_ip_set(
        IPSetId=ip_set_id,
        ChangeToken=change_token,
        Updates=[
            {
                'Action': 'INSERT',
                'IPSetDescriptor': {
                    'Type': 'IPV4',
                    'Value': f"{ip_address}/32"
                }
            }
        ]
    )