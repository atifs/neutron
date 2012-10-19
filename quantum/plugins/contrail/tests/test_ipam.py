import sys
sys.path.insert(2, '/opt/stack/python-quantumclient')
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

import pdb; pdb.set_trace()
net_req = {'name': 'vn1'}
net_rsp = quantum.create_network({'network': net_req})

ipam_req = {'name': 'ipam1',
            'mgmt': {'method': 'dhcp',
                 'options': [{'option': 'opt_1', 'value': 'opt_1_value'},
                             {'option': 'opt_2', 'value': 'opt_2_value'}]
                    }
           }
ipam_rsp = quantum.create_ipam({'ipam': ipam_req})

ipam_req = {'name': 'ipam2',
            'mgmt': {'method': 'dhcp',
                 'options': [{'option': 'opt_3', 'value': 'opt_3_value'},
                             {'option': 'opt_4', 'value': 'opt_4_value'}]
                    }
           }
ipam_rsp = quantum.create_ipam({'ipam': ipam_req})

subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '1.1.1.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': 'default-domain:default-project:ipam1'}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '1.1.2.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': 'default-domain:default-project:ipam2'}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '2.1.1.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': 'default-domain:default-project:ipam1'}
subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

subnet_req = {'network_id': net_rsp['network']['id'],
              'cidr': '2.1.2.0/24',
              'ip_version': 4,
              'contrail:ipam_fq_name': 'default-domain:default-project:ipam2'}

subnet_rsp = quantum.create_subnet({'subnet': subnet_req})

import pdb; pdb.set_trace()
print quantum.list_networks()
print quantum.list_ipams()
