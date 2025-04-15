import boto3
from flask import render_template, request, redirect, url_for
from app import app
from app.ml_model import check_malicious_request

# AWS WAF setup (not used locally, but included for completeness)
waf_client = boto3.client('waf-regional', region_name=app.config['AWS_REGION'])

def create_waf_rule():
    response = waf_client.create_rule(
        Name='MaliciousRequestRule',
        MetricName='MaliciousRequestRule',
        ChangeToken=waf_client.get_change_token()['ChangeToken'],
        Predicates=[
            {
                'DataId': 'IPSet-ID',  # Replace with your actual IPSet ID when deploying
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

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('forbidden'))
    return render_template('login.html')

@app.route('/forbidden')
def forbidden():
    return render_template('Forbidden.html')  # Ensure you have a Forbidden.html template

@app.route('/about')
def about():
    return render_template('about.html')

blocked_ips = set()

@app.before_request
def waf_middleware():
    # Extract body: use request.form for POST form data, otherwise raw data
    if request.method == 'POST' and request.form:
        body = '&'.join([f"{k}={v}" for k, v in request.form.items()])
    else:
        body = request.get_data(as_text=True)
    
    request_data = {
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'body': body,
        'ip': request.remote_addr
    }
    print("Request Data:", request_data)  # Debug
    
    if request_data['ip'] in blocked_ips:
        print("IP Blocked")
        return "Blocked: IP Restricted", 403
    
    if check_malicious_request(request_data):
        print("Malicious Detected")
        blocked_ips.add(request_data['ip'])
        # Optionally update AWS WAF IP set (commented out for local testing)
        # update_ip_set(request_data['ip'])
        return "Blocked: Malicious Request Detected", 403
    print("Request Allowed")