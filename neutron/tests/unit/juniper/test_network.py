import sys
sys.path.insert(2, '/opt/stack/python-quantumclient')
from pprint import pformat

from quantumclient.quantum import client
from quantumclient.client import HTTPClient

httpclient = HTTPClient(username='admin',
                        tenant_name='admin',
                        password='contrail123',
                        #region_name=self._region_name,
                        auth_url='http://localhost:5000/v2.0')
httpclient.authenticate()

OS_URL = httpclient.endpoint_url
OS_TOKEN = httpclient.auth_token
quantum = client.Client('2.0', endpoint_url=OS_URL, token = OS_TOKEN)

print "Creating network VN1"
net_req = {'name': 'vn1'}
net_rsp = quantum.create_network({'network': net_req})
net_id = net_rsp['network']['id']

print "Creating policy pol1"
policy_req = {'name': 'pol1'}

policy_rsp = quantum.create_policy({'policy': policy_req})
policy1_fq_name = policy_rsp['policy']['fq_name']

print "Creating policy pol2"
policy_req = {'name': 'pol2'}
policy_rsp = quantum.create_policy({'policy': policy_req})
policy2_fq_name = policy_rsp['policy']['fq_name']

print "Setting VN1 policy to [pol1]"
net_req = {'contrail:policys': [policy1_fq_name]}
net_rsp = quantum.update_network(net_id, {'network': net_req})

print "Setting VN1 policy to [pol1, pol2]"
net_req = {'contrail:policys': [policy1_fq_name, policy2_fq_name]}
net_rsp = quantum.update_network(net_id, {'network': net_req})

print "Setting VN1 policy to [pol2]"
net_req = {'contrail:policys': [policy2_fq_name]}
net_rsp = quantum.update_network(net_id, {'network': net_req})

print pformat(quantum.show_network(net_id)) + "\n"
