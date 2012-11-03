import json
import sys
sys.path.insert(2, '/opt/stack/python-quantumclient')
from pprint import pformat

from quantumclient.quantum import client
from quantumclient.client import HTTPClient

from vnc_api_gen.resource_xsd import *

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
net1_id = net_rsp['network']['id']
net1_fqname = net_rsp['network']['contrail:fq_name']
net1_fqname_str = ':'.join(net1_fqname)

print "Creating network VN2"
net_req = {'name': 'vn2'}
net_rsp = quantum.create_network({'network': net_req})
net2_id = net_rsp['network']['id']
net2_fqname = net_rsp['network']['contrail:fq_name']
net2_fqname_str = ':'.join(net2_fqname)

print "Creating IPAM ipam1"
dhcp_options = [{'dhcp_option_name': 'opt1', 'dhcp_option_value': 'opt1_value'},
                      {'dhcp_option_name': 'opt2', 'dhcp_option_value': 'opt2_value'}]
dhcp_options_list =  DhcpOptionsListType(dhcp_options)
ipam_mgmt = IpamType.factory(ipam_method = 'dhcp',
                             dhcp_option_list = dhcp_options_list)
ipam_mgmt_dict = \
    json.loads(json.dumps(ipam_mgmt,
                    default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
ipam_req = {'name': 'ipam1',
            'mgmt': ipam_mgmt_dict
           }
ipam_rsp = quantum.create_ipam({'ipam': ipam_req})
ipam1_fq_name = ipam_rsp['ipam']['fq_name']
ipam1_id = ipam_rsp['ipam']['id']

print "Creating subnet 10.1.1.0/24 linking to VN1-IPAM1"
subnet_req = {'network_id': net1_id,
              'cidr': '10.1.1.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': ipam1_fq_name}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

print "Creating subnet 20.1.1.0/24 linking to VN2-IPAM1"
subnet_req = {'network_id': net2_id,
              'cidr': '20.1.1.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': ipam1_fq_name}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

print "Creating policy pol1"
np_rules = [PolicyRuleType(None, '<>', 'pass', 'any',
                [AddressType(virtual_network = 'local')], [PortType(-1, -1)], None,
                [AddressType(virtual_network = net2_fqname_str)], [PortType(-1, -1)], None)]
pol_entries = PolicyEntriesType(np_rules)
pol_entries_dict = \
    json.loads(json.dumps(pol_entries,
                    default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
policy_req = {'name': 'pol1',
              'entries': pol_entries_dict}

policy_rsp = quantum.create_policy({'policy': policy_req})
policy1_fq_name = policy_rsp['policy']['fq_name']

print "Creating policy pol2"
np_rules = [PolicyRuleType(None, '<>', 'pass', 'any',
                [AddressType(virtual_network = 'local')], [PortType(-1, -1)], None,
                [AddressType(virtual_network = net1_fqname_str)], [PortType(-1, -1)], None)]
pol_entries = PolicyEntriesType(np_rules)
pol_entries_dict = \
    json.loads(json.dumps(pol_entries,
                    default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
policy_req = {'name': 'pol2',
              'entries': pol_entries_dict}

policy_rsp = quantum.create_policy({'policy': policy_req})
policy2_fq_name = policy_rsp['policy']['fq_name']

print "Setting VN1 policy to [pol1]"
net_req = {'contrail:policys': [policy1_fq_name]}
net_rsp = quantum.update_network(net1_id, {'network': net_req})

print "Setting VN2 policy to [pol2]"
net_req = {'contrail:policys': [policy2_fq_name]}
net_rsp = quantum.update_network(net2_id, {'network': net_req})

print pformat(quantum.list_policys()) + "\n"
print pformat(quantum.show_network(net1_id)) + "\n"
