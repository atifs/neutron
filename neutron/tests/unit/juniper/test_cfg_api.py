import logging

from ginkgo import Service
from fabric.api import env
from fabric.api import run
from fabric.context_managers import settings

import eventlet
import os
import sys
sys.path.insert(0, os.getcwd())
from quantum.server import main as server
#eventlet.monkey_patch(thread=False)

import uuid
import time
import errno
import socket
import subprocess
import vnc_cfg_api_server
from vnc_api_common import exceptions as vnc_exceptions

import unittest
from vnc_api import *

import json
sys.path.insert(2, '/opt/stack/python-quantumclient')
from pprint import pformat
from quantumclient.quantum import client
from quantumclient.client import HTTPClient
from quantumclient.common import exceptions as q_exceptions

CASS_SVR_IP = '127.0.0.1'
CASS_SVR_PORT = '9160'

ZK_SVR_IP = '127.0.0.1'
ZK_SVR_PORT = '2181'

KEYSTONE_SVR_IP = '127.0.0.1'
KEYSTONE_SVR_PORT = '5000'

IFMAP_SVR_IP = '127.0.0.1'
IFMAP_SVR_PORT = '8443'
# publish user
IFMAP_SVR_USER = 'test'
IFMAP_SVR_PASSWD = 'test'
# subscribe users
IFMAP_SVR_USER2 = 'test2'
IFMAP_SVR_PASSWD2 = 'test2'
IFMAP_SVR_USER3 = 'test3'
IFMAP_SVR_PASSWD3 = 'test3'

#API_SVR_IP = '0.0.0.0'
API_SVR_IP = '10.1.2.195'
API_SVR_PORT = '8082'

QUANTUM_SVR_IP = '127.0.0.1'
QUANTUM_SVR_PORT = '9696'

BGP_SVR_IP = '127.0.0.1'
BGP_SVR_PORT = '8179'
BGP_SANDESH_PORT = '8083'

COLL_SVR_IP = '127.0.0.1'
COLL_SVR_PORT = '8090'

HTTP_SVR_PORT = '8091'

ZK_LOC='/home/contrail/source/zookeeper-3.4.4/'
KEYSTONE_LOC='/opt/stack/keystone/'
IFMAP_SVR_LOC='/home/contrail/source/ifmap-server/'
API_SVR_LOC='/usr/local/lib/python2.7/dist-packages/vnc_cfg_api_server-0.1dev-py2.7.egg/'
QUANTUM_SVR_LOC='/opt/stack/quantum/'
SCHEMA_TRANSFORMER_LOC='/usr/local/lib/python2.7/dist-packages/schema_transformer-0.1dev-py2.7.egg/schema_transformer/'
CTRLPLANE_BIN='/home/contrail/build/bin/'
CTRLPLANE_LIB='/home/contrail/build/lib/'
#KLM_LOC=CTRLPLANE_ROOT + '/src/vnsw/dp/'
#AGENT_LOC=CTRLPLANE_ROOT + '/build/debug/vnsw/agent/'

class CRUDTestCase(unittest.TestCase):
    def setUp(self):
        httpclient = HTTPClient(username='admin',
                                tenant_name='admin',
                                password='contrail123',
                                #region_name=self._region_name,
                                auth_url='http://localhost:5000/v2.0')
        httpclient.authenticate()
        
        #OS_URL = httpclient.endpoint_url
        OS_URL = 'http://%s:%s/' %(QUANTUM_SVR_IP, QUANTUM_SVR_PORT)
        OS_TOKEN = httpclient.auth_token
        self._quantum = client.Client('2.0', endpoint_url=OS_URL, token = OS_TOKEN)

        self._vnc_lib = VncApi('user1', 'password1', 'default-domain',
                               API_SVR_IP, API_SVR_PORT, '/')
    #end setUp
        
    def _test_network(self):
        # Create; Verify with show + list 
        net_name = 'vn1'
        net_req = {'name': net_name}
        net_rsp = self._quantum.create_network({'network': net_req})
        net_admin_state = net_rsp['network']['admin_state_up']
        # TODO create with partial perms (only user)

        # Read
        net_id = net_rsp['network']['id']
        net_rsp = self._quantum.show_network(net_id)
        self.assertEqual(net_rsp['network']['name'], net_name)

        net_rsp = self._quantum.list_networks()
        self.assertTrue(net_name in [network['name'] \
                                     for network in net_rsp['networks']])

        # Update property
        net_req = {'admin_state_up': not net_admin_state}
        net_rsp = self._quantum.update_network(net_id, {'network': net_req})
        self.assertNotEqual(net_admin_state,
                            net_rsp['network']['admin_state_up'])
 
        # Delete; Verify with show + list
        self._quantum.delete_network(net_id)

        with self.assertRaisesRegexp(q_exceptions.QuantumClientException,
                                     'could not be found') as e:
            self._quantum.show_network(net_id)

        net_rsp = self._quantum.list_networks()
        self.assertFalse(net_name in [network['name'] \
                                     for network in net_rsp['networks']])
    #end test_network

    def test_subnet(self):
        # Create; Verify with show + list 
        param = {'contrail:fq_name': [VirtualNetwork().get_fq_name()]}
        nets = self._quantum.list_networks(**param)['networks']
        self.assertEqual(len(nets), 1)
        net_id = nets[0]['id']

        ipam_fq_name = NetworkIpam().get_fq_name()

        cidr = u'1.1.1.0/24'
        gw = u'1.1.1.254'
        subnet_req = {'network_id': net_id,
                      'cidr': cidr,
                      'ip_version': 4,
                      'contrail:ipam_fq_name': ipam_fq_name}
        subnet_rsp = self._quantum.create_subnet({'subnet': subnet_req})
        subnet_cidr = subnet_rsp['subnet']['cidr']
        subnet_gw = subnet_rsp['subnet']['gateway_ip']
        self.assertEqual(subnet_cidr, cidr)
        self.assertEqual(subnet_gw, gw)

    #end test_subnet

    def test_ipam(self):
        print "Creating ipam with ipam1"
        ipam_name = 'ipam1'
        ipam_req = {'name': ipam_name}
        ipam_rsp = self._quantum.create_ipam({'ipam': ipam_req})
        #ipam_admin_state = ipam_rsp['ipam']['admin_state_up']

        # Read
        ipam_id = ipam_rsp['ipam']['id']
        ipam_rsp = self._quantum.show_ipam(ipam_id)
        self.assertEqual(ipam_rsp['ipam']['name'], ipam_name)

        ipam_rsp = self._quantum.list_ipams()
        self.assertTrue(ipam_name in [ipam['name'] \
                                     for ipam in ipam_rsp['ipams']])

        # TODO Update property
        #ipam_req = {'admin_state_up': not ipam_admin_state}
        #ipam_rsp = self._quantum.update_ipam(ipam_id, {'ipam': ipam_req})
        #self.assertNotEqual(ipam_admin_state,
        #                    ipam_rsp['ipam']['admin_state_up'])
 
        # Delete; Verify with show + list
        self._quantum.delete_ipam(ipam_id)

        with self.assertRaisesRegexp(q_exceptions.QuantumClientException,
                                     'could not be found') as e:
            self._quantum.show_ipam(ipam_id)

        ipam_rsp = self._quantum.list_ipams()
        self.assertFalse(ipam_name in [ipam['name'] \
                                     for ipam in ipam_rsp['ipams']])

    #end test_ipam

    def _test_same_name(self):
        print "Creating net with name vn1"
        net_name = 'vn1'
        net_req = {'name': net_name}
        net_rsp = self._quantum.create_network({'network': net_req})

        print "Creating ipam with name vn1"
        ipam_req = {'name': net_name}
        ipam_rsp = self._quantum.create_ipam({'ipam': ipam_req})

        print "Making sure no duplicates in net-list and ipam-list"
        net_name_list = [net['name'] for net in self._quantum.list_networks()['networks']]
        net_name_set = set(net_name_list)
        self.assertEqual(len(net_name_list), len(net_name_set))

        ipam_name_list = [ipam['name'] for ipam in self._quantum.list_ipams()['ipams']]
        ipam_name_set = set(ipam_name_list)
        self.assertEqual(len(ipam_name_list), len(ipam_name_set))
    #end test_same_name

    def test_port(self):
        print "Creating network VN1, subnet 10.1.1.0/24"
        net_req = {'name': 'vn1'}
        net_rsp = self._quantum.create_network({'network': net_req})
        net1_id = net_rsp['network']['id']
        net1_fq_name = net_rsp['network']['contrail:fq_name']
        net1_fq_name_str = ':'.join(net1_fq_name)
        sn1_id = self._create_subnet(u'10.1.1.0/24', net1_id)

        print "Creating port"
        instance_id = str(uuid.uuid4())
        port_req = {'network_id': net1_id,
                    'device_id': instance_id,
                    'compute_node_id': 'test-server'}
        port_rsp = self._quantum.create_port({'port': port_req})
        port_id = port_rsp['port']['id']
        port_admin_state = port_rsp['port']['admin_state_up']

        print "Reading port"
        port_rsp = self._quantum.show_port(port_id)
        self.assertEqual(port_rsp['port']['device_id'], instance_id)
        fixed_ips = port_rsp['port']['fixed_ips']
        self.assertEqual(len(fixed_ips), 1)
        self.assertEqual(fixed_ips[0]['subnet_id'], sn1_id)
        #TODO assert addr is in subnet and not in reserved range

        print "Updating port"
        port_req = {'admin_state_up': not port_admin_state}
        port_rsp = self._quantum.update_port(port_id, {'port': port_req})
        self.assertNotEqual(port_admin_state,
                            port_rsp['port']['admin_state_up'])

        print "Listing port"
        port_rsp = self._quantum.list_ports(device_id = [instance_id])
        self.assertIn(port_id, [port['id'] for port in port_rsp['ports']])
        port_rsp = self._quantum.list_ports(network_id = [net1_id])
        self.assertIn(port_id, [port['id'] for port in port_rsp['ports']])

        # Delete; Verify with show + list
        print "Deleting port"
        self._quantum.delete_port(port_id)

        with self.assertRaises(q_exceptions.QuantumClientException) as e:
            self._quantum.show_port(port_id)

        port_rsp = self._quantum.list_ports(device_id = [instance_id])
        self.assertFalse(port_id in [port['id'] \
                                     for port in port_rsp['ports']])
    #end test_port

    def test_policy(self):
        print "Creating policy pol1"
        np_rules = [PolicyRuleType(None, '<>', 'pass', 'any',
                        [AddressType(virtual_network = 'local')], [PortType(-1, -1)], None,
                        [AddressType(virtual_network = 'any')], [PortType(-1, -1)], None)]
        pol_entries = PolicyEntriesType(np_rules)
        pol_entries_dict = \
            json.loads(json.dumps(pol_entries,
                            default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
        policy_req = {'name': 'pol1',
                      'entries': pol_entries_dict}
        
        policy_rsp = self._quantum.create_policy({'policy': policy_req})
        policy1_fq_name = policy_rsp['policy']['fq_name']
        policy1_id = policy_rsp['policy']['id']

        print "Reading policy pol1"
        policy_rsp = self._quantum.show_policy(policy1_id)
        self.assertEqual(len(policy_rsp['policy']['entries']), 1)

        print "Updating policy pol1"
        np_rules = [PolicyRuleType(None, '->', 'deny', 'any',
                        [AddressType(virtual_network = 'local')], [PortType(-1, -1)], None,
                        [AddressType(virtual_network = 'any')], [PortType(-1, -1)], None)]
        pol_entries = PolicyEntriesType(np_rules)
        pol_entries_dict = \
            json.loads(json.dumps(pol_entries,
                            default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
        policy_req = {'entries': pol_entries_dict}
        policy_rsp = self._quantum.update_policy(policy1_id, {'policy': policy_req})
    #end test_policy

    def test_policy_link_vns(self):
        net1_id, net2_id, net1_fq_name, net2_fq_name = self._create_two_vns()
        net1_fq_name_str = ':'.join(net1_fq_name)
        net2_fq_name_str = ':'.join(net2_fq_name)

        print "Creating policy pol1"
        np_rules = [PolicyRuleType(None, '<>', 'pass', 'any',
                        [AddressType(virtual_network = 'local')], [PortType(-1, -1)], None,
                        [AddressType(virtual_network = net2_fq_name_str)], [PortType(-1, -1)], None)]
        pol_entries = PolicyEntriesType(np_rules)
        pol_entries_dict = \
            json.loads(json.dumps(pol_entries,
                            default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
        policy_req = {'name': 'pol1',
                      'entries': pol_entries_dict}
        
        policy_rsp = self._quantum.create_policy({'policy': policy_req})
        policy1_id = policy_rsp['policy']['id']
        policy1_fq_name = policy_rsp['policy']['fq_name']
        
        print "Creating policy pol2"
        np_rules = [PolicyRuleType(None, '<>', 'pass', 'any',
                        [AddressType(virtual_network = 'local')], [PortType(-1, -1)], None,
                        [AddressType(virtual_network = net1_fq_name_str)], [PortType(-1, -1)], None)]
        pol_entries = PolicyEntriesType(np_rules)
        pol_entries_dict = \
            json.loads(json.dumps(pol_entries,
                            default=lambda o: {k:v for k, v in o.__dict__.iteritems()}))
        policy_req = {'name': 'pol2',
                      'entries': pol_entries_dict}
        
        policy_rsp = self._quantum.create_policy({'policy': policy_req})
        policy2_id = policy_rsp['policy']['id']
        policy2_fq_name = policy_rsp['policy']['fq_name']
        
        print "Setting VN1 policy to [pol1]"
        net_req = {'contrail:policys': [policy1_fq_name]}
        net_rsp = self._quantum.update_network(net1_id, {'network': net_req})
        
        print "Setting VN2 policy to [pol2]"
        net_req = {'contrail:policys': [policy2_fq_name]}
        net_rsp = self._quantum.update_network(net2_id, {'network': net_req})
        
        instance_id = str(uuid.uuid4())
        port_req = {'network_id': net1_id,
                    'device_id': instance_id,
                    'compute_node_id': 'test-server'}
        port_rsp = self._quantum.create_port({'port': port_req})
        port_id = port_rsp['port']['id']

        port_rsp = self._quantum.list_ports(device_id = [instance_id])
        self.assertIn(port_id, [port['id'] for port in port_rsp['ports']])

        self._quantum.delete_port(port_id)
        self._delete_two_vns(net1_id, net2_id)

        self._quantum.delete_policy(policy1_id)
        self._quantum.delete_policy(policy2_id)
    #end test_policy_link_vns

    def test_floating_ip(self):
        net1_id, net2_id, net1_fq_name, net2_fq_name = \
                 self._create_two_vns(vn1_name = 'pvt-vn', vn2_name = 'pub-vn')

        # create floating ip pool from public network
        pub_vn_obj = self._vnc_lib.virtual_network_read(id = net2_id)
        fip_pool_obj = FloatingIpPool('pub-fip-pool', pub_vn_obj)
        self._vnc_lib.floating_ip_pool_create(fip_pool_obj)

        # allow current project to pick from pool
        proj_fq_name = ['default-domain', 'demo']
        proj_obj = self._vnc_lib.project_read(fq_name = proj_fq_name)
        proj_obj.add_floating_ip_pool(fip_pool_obj)
        self._vnc_lib.project_update(proj_obj)

        # list pools available for current project
        fip_pool_nets = self._quantum.list_networks(external = True)
        fip_pool_net_id = fip_pool_nets['networks'][0]['id']

        # allocate couple of floating ips
        fip_dicts = []
        for i in range(2):
            fip_req = {'floatingip': {'floating_network_id': fip_pool_net_id,
                                      'tenant_id': proj_obj.uuid} }
            fip_resp = self._quantum.create_floatingip(fip_req)
            fip_dicts.append(fip_resp['floatingip'])
            print "Got floating-ip %s" %(fip_dicts[i]['floating_ip_address'])

        # list floating ips available for current project
        fip_resp = self._quantum.list_floatingips(tenant_id = proj_obj.uuid)
        print "Floating IP list: " + pformat(fip_resp)
        fip_list = fip_resp['floatingips']
        self.assertEqual(len(fip_list), 2)

        # create instance
        instance_id, port_id, net_id = self._create_instance()

        # associate floating ip
        fip_id = fip_dicts[0]['id']
        fip_req = {'floatingip': {'port_id': port_id} }
        fip_resp = self._quantum.update_floatingip(fip_id, fip_req)

        # release the floating ips
        fip_req = {'floatingip': {'port_id': None} }
        fip_resp = self._quantum.update_floatingip(fip_id, fip_req)

        # delete instance
        self._delete_instance(instance_id, port_id, net_id)

        # delete the floating ips
        for i in range(2):
            self._quantum.delete_floatingip(fip_dicts[i]['id'])

        fip_resp = self._quantum.list_floatingips(tenant_id = proj_obj.uuid)
        fip_list = fip_resp['floatingips']
        self.assertEqual(len(fip_list), 0)
    #end test_floating_ip

    def test_bgp_router(self):
        fq_name = ['default-domain', 'default-project', 'ip-fabric', '__default__']
        ri_obj = self._vnc_lib.routing_instance_read(fq_name = fq_name)

        bgp_addr_fams = AddressFamilies(['inet-vpn'])
        bgp_sess_attrs = [BgpSessionAttributes(address_families = bgp_addr_fams)]
        bgp_sessions = [BgpSession(attributes = bgp_sess_attrs)]
        bgp_peering_attrs = BgpPeeringAttributes(session = bgp_sessions)

        bgp_router1 = BgpRouter('bgp-router1', ri_obj)
        bgp_router2 = BgpRouter('bgp-router2', ri_obj)
        bgp_router1.add_bgp_router(bgp_router2, bgp_peering_attrs)
        bgp_router2.add_bgp_router(bgp_router1, bgp_peering_attrs)

        self._vnc_lib.bgp_router_create(bgp_router1)
        self._vnc_lib.bgp_router_create(bgp_router2)
        with self.assertRaises(vnc_exceptions.RefsExistError) as e:
            self._vnc_lib.bgp_router_delete(id = bgp_router1.uuid)

        bgp_router1.set_bgp_router_list([], [])
        bgp_router2.set_bgp_router_list([], [])

        self._vnc_lib.bgp_router_update(bgp_router1)
        self._vnc_lib.bgp_router_update(bgp_router2)
        self._vnc_lib.bgp_router_delete(id = bgp_router1.uuid)
        self._vnc_lib.bgp_router_delete(id = bgp_router2.uuid)
    #end test_bgp_router

    def test_instance(self):
        instance_id, port_id, net_id = self._create_instance()
        port_id = self._delete_instance(instance_id, port_id, net_id)
    #end test_instance

    def _create_instance(self, net_id = None, vrouter_name = 'test-vrouter'):
        if not net_id:
            net_id, net_fq_name = self._create_vn_subnet('vn1', '10.1.1.0/24')

        print "Creating instance/port"
        instance_id = str(uuid.uuid4())
        port_req = {'network_id': net_id,
                    'device_id': instance_id,
                    'compute_node_id': vrouter_name}
        port_rsp = self._quantum.create_port({'port': port_req})
        port_id = port_rsp['port']['id']

        return instance_id, port_id, net_id
    #end _create_instance

    def _delete_instance(self, instance_id, port_id, net_id = None):
        self._quantum.delete_port(port_id)
        self._delete_vn_subnet(net_id)
    #end _delete_instance

    def _create_subnet(self, cidr, net_id, ipam_fq_name = None):
        if not ipam_fq_name:
            ipam_fq_name = NetworkIpam().get_fq_name()

        subnet_req = {'network_id': net_id,
                      'cidr': cidr,
                      'ip_version': 4,
                      'contrail:ipam_fq_name': ipam_fq_name}
        subnet_rsp = self._quantum.create_subnet({'subnet': subnet_req})
        subnet_cidr = subnet_rsp['subnet']['cidr']
        self.assertEqual(subnet_cidr, cidr)
        return subnet_rsp['subnet']['id']
    #end _create_subnet

    def _create_vn_subnet(self, vn_name, subnet):
        print "Creating network %s, subnet %s" %(vn_name, subnet)
        net_req = {'name': vn_name}
        net_rsp = self._quantum.create_network({'network': net_req})
        net_id = net_rsp['network']['id']
        net_fq_name = net_rsp['network']['contrail:fq_name']
        self._create_subnet(subnet, net_id)

        return net_id, net_fq_name
    #end _create_vn_subnet

    def _delete_vn_subnet(self, vn_id):
        subnets_rsp = self._quantum.list_subnets(network_id = vn_id)
        for subnet in subnets_rsp['subnets']:
            self._quantum.delete_subnet(subnet['id'])

        self._quantum.delete_network(vn_id)
    #end _delete_vn_subnet

    def _create_two_vns(self, vn1_name = None, vn1_tenant = None,
                              vn2_name = None, vn2_tenant = None):
        if not vn1_name:
            vn1_name = 'vn1'
        if not vn2_name:
            vn2_name = 'vn2'

        net1_id, net1_fq_name = self._create_vn_subnet(vn1_name, '10.1.1.0/24')
        net1_fq_name_str = ':'.join(net1_fq_name)

        net2_id, net2_fq_name = self._create_vn_subnet(vn2_name, '10.1.1.0/24')
        net2_fq_name_str = ':'.join(net2_fq_name)

        return net1_id, net2_id, net1_fq_name, net2_fq_name
    #end _create_two_vns

    def _delete_two_vns(self, vn1_id, vn2_id):
        self._delete_vn_subnet(vn1_id)
        self._delete_vn_subnet(vn2_id)
    #end _delete_two_vns

#end class CRUDTestCase

class TestBench(Service):
    def __init__(self):
        self._keystone_server = None
        self._ifmap_server = None
        self._api_server = None
        self._quantum_server = None
        self._klm_loaded = False

        self.compute_nodes = [
              ({'mgmt_ip': '192.168.122.99', 'vhost_ip': '192.168.100.3'}),
              #({'mgmt_ip': '192.168.122.161', 'vhost_ip': '192.168.100.4'}),
        ]
    #end __init__

    def do_start(self):
        self.spawn(self.launch_zookeeper)
        self.spawn(self.launch_keystone)
        self.spawn(self.launch_ifmap_server)
        self.spawn(self.launch_api_server)
        self.spawn(self.launch_quantum_plugin)
        self.spawn(self.launch_schema_transformer)
        self.spawn(self.launch_bgp_server)
        #self.spawn(self.launch_klms)
        #self.spawn(self.launch_agents)
        self.spawn(self.launch_tests)
    #end do_start

    def do_reload(self):
        import pdb; pdb.set_trace()
    #end do_reload

    def do_stop(self):
        if self._keystone_server:
            self._keystone_server.kill()
        if self._ifmap_server:
            self._ifmap_server.kill()
        if self._api_server:
            self._api_server.kill()
        if self._quantum_server:
            self._quantum_server.kill()
        if self._bgp_server:
            self._bgp_server.kill()
    #end do_stop

    def launch_zookeeper(self):
        subprocess.Popen([ZK_LOC + '/bin/zkServer.sh', 'start'])
    #end launch_zookeeper

    def launch_keystone(self):
        self._ensure_port_not_listened(KEYSTONE_SVR_IP, KEYSTONE_SVR_PORT)
        logf_out = open('keystone.out', 'w')
        logf_err = open('keystone.err', 'w')
        keystone = subprocess.Popen([KEYSTONE_LOC + '/bin/keystone-all', '--config-file',
                       os.getcwd() + '/keystone.conf', '-d', '--debug'],
                       stdout = logf_out, stderr = logf_err) 
        self._keystone_server = keystone
    #end launch_keystone

    def launch_ifmap_server(self):
        self._ensure_port_not_listened(IFMAP_SVR_IP, IFMAP_SVR_PORT)
        logf_out = open('ifmap-server.out', 'w')
        logf_err = open('ifmap-server.err', 'w')
        maps = subprocess.Popen(['java', '-jar', 'build/irond.jar'],
                   cwd=IFMAP_SVR_LOC, stdout = logf_out, stderr = logf_err) 
        self._ifmap_server = maps
    #end launch_ifmap_server

    def launch_api_server(self):
        self._ensure_port_not_listened(API_SVR_IP, API_SVR_PORT)
        # Wait for IFMAP server to be running before launching api server
        self._block_till_port_listened('ifmap-server', IFMAP_SVR_IP, IFMAP_SVR_PORT)

        args = ['--auth', 'keystone',
                '--reset_config',
                '--listen_ip_addr', API_SVR_IP, '--listen_port', API_SVR_PORT,
                '--ifmap_server_ip', IFMAP_SVR_IP, '--ifmap_server_port', IFMAP_SVR_PORT,
                '--ifmap_username', IFMAP_SVR_USER, '--ifmap_password', IFMAP_SVR_PASSWD,
                '--cassandra_server_ip', CASS_SVR_IP, '--cassandra_server_port', CASS_SVR_PORT,]

        #args_str = '--auth keystone --reset_config'
        #args_str = '--auth keystone'
        #args_str = args_str + ' --listen_ip_addr %s --listen_port %s' %(API_SVR_IP, API_SVR_PORT)
        #args_str = args_str + ' --ifmap_server_ip %s --ifmap_server_port %s' %(IFMAP_SVR_IP,
        #                                                                       IFMAP_SVR_PORT)
        #args_str = args_str + ' --ifmap_username %s --ifmap_password %s' %(IFMAP_SVR_USER,
        #                                                                   IFMAP_SVR_PASSWD)
        #args_str = args_str + ' --cassandra_server_ip %s --cassandra_server_port %s' %(CASS_SVR_IP,
        #                                                                               CASS_SVR_PORT)
        args_str = ' '.join(args)
        #vnc_cfg_api_server.main(args_str)
        api_server = subprocess.Popen(['python', 'vnc_cfg_api_server.py'] + args,
                                      cwd = API_SVR_LOC)
        self._api_server = api_server
    #end launch_api_server

    def launch_quantum_plugin(self):
        self._ensure_port_not_listened(QUANTUM_SVR_IP, QUANTUM_SVR_PORT)
        # Wait for API server to be running before launching Q plugin
        self._block_till_port_listened('api-server', API_SVR_IP, API_SVR_PORT)

        quantum_server = subprocess.Popen([QUANTUM_SVR_LOC + '/bin/quantum-server',
                                           '--config-file=quantum.conf',
                                           '--config-file=contrail_plugin.ini'])
        self._quantum_server = quantum_server
    #end launch_quantum_plugin

    def launch_schema_transformer(self):
        # Wait for API server to be running before launching schema tranformer
        self._block_till_port_listened('api-server', API_SVR_IP, API_SVR_PORT)

        schema_transformer = subprocess.Popen(['python', 'to_bgp.py',
               '--ifmap_server_ip', IFMAP_SVR_IP, '--ifmap_server_port', IFMAP_SVR_PORT,
               '--ifmap_username', IFMAP_SVR_USER2, '--ifmap_password', IFMAP_SVR_PASSWD2,
               '--api_server_ip', API_SVR_IP, '--api_server_port', API_SVR_PORT,
               '--zookeeper_server_ip', ZK_SVR_IP, '--zookeeper_server_port', ZK_SVR_PORT,
               '--collector', COLL_SVR_IP, '--collector_port', COLL_SVR_PORT,
               '--http_server_port', HTTP_SVR_PORT],
               cwd = SCHEMA_TRANSFORMER_LOC)
        self._schema_transformer = schema_transformer
    #end launch_schema_transformer

    def launch_bgp_server(self):
        # Wait for IFMAP server to be running before launching bgp server 
        self._block_till_port_listened('ifmap-server', IFMAP_SVR_IP, IFMAP_SVR_PORT)

        logf_out = open('bgp-server.out', 'w')
        logf_err = open('bgp-server.err', 'w')
        bgp_server = subprocess.Popen(['%s/control-node' %(CTRLPLANE_BIN),
            '--map-server-url', 'https://%s:%s' %(IFMAP_SVR_IP, IFMAP_SVR_PORT),
            '--map-user', IFMAP_SVR_USER3, '--map-password', IFMAP_SVR_PASSWD3,
            '--bgp-port', BGP_SVR_PORT, '--http-server-port', BGP_SANDESH_PORT],
            env = {'LD_LIBRARY_PATH': CTRLPLANE_LIB},
            stdout = logf_out, stderr = logf_err)

        self._bgp_server = bgp_server
    #end launch_bgp_server

    def launch_klms(self):
        env.password="contrail123"
        env.host_string = "192.168.122.161:22"

        mgmt_ips = [cnode['mgmt_ip'] for cnode in self.compute_nodes]
        for cn_ip in mgmt_ips:
            with settings(password = "contrail123",
                          host_string = "%s:22" %(cn_ip),
                          warn_only = True):
                # kill agent + unload klm
                run("ps auxw | grep vnswad | grep -v grep | awk '{ print $2 '} | xargs sudo kill -9")
                run("sudo rmmod vrouter")

        # and launch new instance of klm
        for cn_ip in mgmt_ips:
            with settings(password = "contrail123",
                          host_string = "%s:22" %(cn_ip)):
                run("LD_LIBRARY_PATH=%s/utils sudo -E insmod %s/vrouter.ko" %(KLM_LOC, KLM_LOC))

        self._klm_loaded = True
    #end launch_klms

    def launch_agents(self):
        # Wait for BGP server to be running before launching agents
        self._block_till_port_listened('bgp-server', BGP_SVR_IP, BGP_SVR_PORT)

        # Wait till kernel modules are loaded
        while not self._klm_loaded:
            print "KLM not loaded, retrying in 2 secs"
            time.sleep(2)

        cn_ips = [(cnode['mgmt_ip'], cnode['vhost_ip']) for cnode in self.compute_nodes]
        for mgmt_ip, vhost_ip in cn_ips:
            with settings(user = "root",
                          password = "contrail123",
                          host_string = "%s:22" %(mgmt_ip)):
                run("LD_LIBRARY_PATH=%s/build/lib:%s/utils nohup %s/vnswad -c %s/vnswa_cfg.xml >& /tmp/agent-out < /dev/null &" 
                     %(CTRLPLANE_ROOT, KLM_LOC, AGENT_LOC, CTRLPLANE_ROOT), pty = False)
                run("ifconfig vhost0 %s/24" %(vhost_ip))
                run("route add -net 169.254.0.0 netmask 255.255.0.0 vhost0")
                run("ifconfig eth1 up")
    #end launch_agents

    def launch_tests(self):
        self._block_till_port_listened('quantum-server', QUANTUM_SVR_IP,
                                                         QUANTUM_SVR_PORT)
 
        del sys.argv[1:]
        suite1 = unittest.TestLoader().loadTestsFromTestCase(CRUDTestCase)

        #all_tests = unittest.TestSuite([suite1])
        #unittest.main(defaultTest=all_tests)
        unittest.TextTestRunner(verbosity=2).run(suite1)
    #end launch_tests

    def _ensure_port_not_listened(self, server_ip, server_port):
        try:
            s = socket.create_connection((server_ip, server_port))
            s.close()
            print "IP %s port %s already listened on" %(server_ip, server_port)
        except Exception as err:
            if err.errno == errno.ECONNREFUSED:
                return # all is well
    #end _ensure_port_not_listened

    def _block_till_port_listened(self, server_name, server_ip, server_port):
        svr_running = False
        while not svr_running:
            try:
                s = socket.create_connection((server_ip, server_port))
                s.close()
                svr_running = True
            except Exception as err:
                if err.errno == errno.ECONNREFUSED:
                    print "%s not up, retrying in 2 secs" %(server_name)
                    time.sleep(2)
                else:
                    import pdb; pdb.set_trace()
    #end _block_till_port_listened

#end Class TestBench
