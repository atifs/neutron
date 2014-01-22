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
net_id = net_rsp['network']['id']

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

print "Updating IPAM ipam1"
ipam_req = {'mgmt': {'ipam_method': 'fixed',
                     'dhcp_option_list': {'dhcp_option': [{'dhcp_option_name': 'opt10',
                                                           'dhcp_option_value': 'opt10_value'}]}
                    }
           }
quantum.update_ipam(ipam1_id, {'ipam': ipam_req})

print "Creating IPAM ipam2"
dhcp_options = [{'dhcp_option_name': 'opt3', 'dhcp_option_value': 'opt3_value'},
                      {'dhcp_option_name': 'opt4', 'dhcp_option_value': 'opt4_value'}]
dhcp_options_list =  DhcpOptionsListType(dhcp_options)
ipam_mgmt = IpamType.factory(ipam_method = 'dhcp',
                             dhcp_option_list = dhcp_options_list)
ipam_mgmt_dict = \
    json.loads(json.dumps(ipam_mgmt,
                    default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
ipam_req = {'name': 'ipam2',
            'mgmt': ipam_mgmt_dict
           }
ipam_rsp = quantum.create_ipam({'ipam': ipam_req})
ipam2_fq_name = ipam_rsp['ipam']['fq_name']
ipam2_id = ipam_rsp['ipam']['id']

print "Creating subnet VN1 1.1.1.0/24 linking to ipam1"
subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '1.1.1.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': ipam1_fq_name}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

print "Creating subnet VN1 1.1.2.0/24 linking to ipam2"
subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '1.1.2.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': ipam2_fq_name}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

print "Creating subnet VN1 2.1.1.0/24 linking to ipam1"
subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '2.1.1.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': ipam1_fq_name}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

print "Creating subnet VN1 2.1.2.0/24 linking to ipam2"
subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '2.1.2.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': ipam2_fq_name}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

print pformat(quantum.show_network(net_id)) + "\n"
print pformat(quantum.list_ipams()) + "\n"
