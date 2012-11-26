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

import unittest
from vnc_api import *

import json
sys.path.insert(2, '/opt/stack/python-quantumclient')
from pprint import pformat
from quantumclient.quantum import client
from quantumclient.client import HTTPClient
from quantumclient.common import exceptions

CASS_SVR_IP = '127.0.0.1'
CASS_SVR_PORT = '9160'

ZK_SVR_IP = '127.0.0.1'
ZK_SVR_PORT = '2181'

KEYSTONE_SVR_IP = '127.0.0.1'
KEYSTONE_SVR_PORT = '5000'

IFMAP_SVR_IP = '127.0.0.1'
IFMAP_SVR_PORT = '8443'
# publish user
#IFMAP_SVR_USER = 'test'
#IFMAP_SVR_PASSWD = 'test'
IFMAP_SVR_USER = 'control-node-3'
IFMAP_SVR_PASSWD = 'control-node-3'
# subscribe users
IFMAP_SVR_USER2 = 'test2'
IFMAP_SVR_PASSWD2 = 'test2'
IFMAP_SVR_USER3 = 'test3'
IFMAP_SVR_PASSWD3 = 'test3'

API_SVR_IP = '127.0.0.1'
API_SVR_PORT = '8082'

QUANTUM_SVR_IP = '127.0.0.1'
QUANTUM_SVR_PORT = '9696'

BGP_SVR_IP = '127.0.0.1'
BGP_SVR_PORT = '9023'
BGP_SANDESH_PORT = '9024'

ZK_LOC='/home/contrail/source/zookeeper-3.4.4/'
KEYSTONE_LOC='/opt/stack/keystone/'
IFMAP_SVR_LOC='/home/contrail/source/ifmap-server/'
QUANTUM_SVR_LOC='/opt/stack/quantum/'
#SCHEMA_TRANSFORMER_LOC='/usr/local/lib/python2.7/dist-packages/schema_transformer-0.1dev-py2.7.egg/schema_transformer/'
SCHEMA_TRANSFORMER_LOC='/home/contrail/source/ctrlplane/src/cfgm/schema-transformer/'
CTRLPLANE_ROOT='/home/contrail/source/ctrlplane'
BGP_SVR_ROOT=CTRLPLANE_ROOT
KLM_LOC=CTRLPLANE_ROOT + '/src/vnsw/dp/'
AGENT_LOC=CTRLPLANE_ROOT + '/build/debug/vnsw/agent/'

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

        with self.assertRaisesRegexp(exceptions.QuantumClientException,
                                     'could not be found') as e:
            self._quantum.show_network(net_id)

        net_rsp = self._quantum.list_networks()
        self.assertFalse(net_name in [network['name'] \
                                     for network in net_rsp['networks']])
    #end test_network

    def _test_subnet(self):
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

    def _test_port(self):
        print "Creating network VN1, subnet 10.1.1.0/24"
        net_req = {'name': 'vn1', 'tenant_id': 'test-tenant'}
        net_rsp = self._quantum.create_network({'network': net_req})
        net1_id = net_rsp['network']['id']
        net1_fq_name = net_rsp['network']['contrail:fq_name']
        net1_fq_name_str = ':'.join(net1_fq_name)
        sn1_id = self._create_subnet(u'10.1.1.0/24', net1_id)

        print "Creating port"
        instance_id = str(uuid.uuid4())
        port_req = {'network_id': net1_id, 'tenant_id': 'test-tenant',
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
        port_rsp = self._quantum.list_ports(tenant_id = ['test-tenant'])
        self.assertIn(port_id, [port['id'] for port in port_rsp['ports']])

        # Delete; Verify with show + list
        print "Deleting port"
        self._quantum.delete_port(port_id)

        with self.assertRaises(exceptions.QuantumClientException) as e:
            self._quantum.show_port(port_id)

        port_rsp = self._quantum.list_ports(device_id = [instance_id])
        self.assertFalse(port_id in [port['id'] \
                                     for port in port_rsp['ports']])
    #end test_port

    def _test_policy(self):
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

    def _test_policy_link_vns(self):
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
        policy2_fq_name = policy_rsp['policy']['fq_name']
        
        print "Setting VN1 policy to [pol1]"
        net_req = {'contrail:policys': [policy1_fq_name]}
        net_rsp = self._quantum.update_network(net1_id, {'network': net_req})
        
        print "Setting VN2 policy to [pol2]"
        net_req = {'contrail:policys': [policy2_fq_name]}
        net_rsp = self._quantum.update_network(net2_id, {'network': net_req})
        
        # Operational (interface directly with vnc-lib)
        # TODO go thru quantum in future
        #instance_id = str(uuid.uuid4())
        #port_req = {'network_id': net1_id, 'tenant_id': 'test-tenant',
        #            'device_id': instance_id,
        #            'compute_node_id': 'test-server'}
        #port_rsp = self._quantum.create_port({'port': port_req})
        #port_id = port_rsp['port']['id']

        #port_rsp = self._quantum.list_ports(device_id = [instance_id])
        #self.assertIn(port_id, [port['id'] for port in port_rsp['ports']])

    #end test_policy_link_vns

    def test_floating_ip(self):
        net1_id, net2_id, net1_fq_name, net2_fq_name = \
                 self._create_two_vns('pvt-vn', 'pub-vn')

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
        for i in range(2):
            fip_req = {'floatingip': {'floating_network_id': fip_pool_net_id,
                                      'tenant_id': proj_obj.uuid} }
            fip_resp = self._quantum.create_floatingip(fip_req)
            print "Got floating-ip %s" %(fip_resp['floatingip']['floating_ip_address'])

        # list floating ips available for current project
        fip_list = self._quantum.list_floatingips(tenant_id = proj_obj.uuid)
        print "Floating IP list: " + pformat(fip_list)

    #end test_floating_ip

    def _create_two_vns(self, vn1_name = None, vn2_name = None):
        if not vn1_name:
            vn1_name = 'vn1'
        if not vn2_name:
            vn2_name = 'vn2'

        print "Creating network %s, subnet 10.1.1.0/24" %(vn1_name)
        net_req = {'name': vn1_name}
        net_rsp = self._quantum.create_network({'network': net_req})
        net1_id = net_rsp['network']['id']
        net1_fq_name = net_rsp['network']['contrail:fq_name']
        net1_fq_name_str = ':'.join(net1_fq_name)
        self._create_subnet(u'10.1.1.0/24', net1_id)

        print "Creating network %s, subnet 20.1.1.0/24" %(vn2_name)
        net_req = {'name': vn2_name}
        net_rsp = self._quantum.create_network({'network': net_req})
        net2_id = net_rsp['network']['id']
        net2_fq_name = net_rsp['network']['contrail:fq_name']
        net2_fq_name_str = ':'.join(net2_fq_name)
        self._create_subnet(u'20.1.1.0/24', net2_id)

        return net1_id, net2_id, net1_fq_name, net2_fq_name
    #end _create_two_vns

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

#end class CRUDTestCase

class TestBench(Service):
    def __init__(self):
        self._keystone_server = None
        self._ifmap_server = None
        self._quantum_server = None
        self._klm_loaded = False

        self.compute_nodes = [
              ({'mgmt_ip': '192.168.122.99', 'vhost_ip': '192.168.100.3'}),
              #({'mgmt_ip': '192.168.122.161', 'vhost_ip': '192.168.100.4'}),
        ]
    #end __init__

    def do_start(self):
        self.spawn(self.launch_zookeeper)
        #self.spawn(self.launch_keystone)
        self.spawn(self.launch_ifmap_server)
        self.spawn(self.launch_api_server)
        self.spawn(self.launch_quantum_plugin)
        #self.spawn(self.launch_schema_transformer)
        #self.spawn(self.launch_bgp_server)
        #self.spawn(self.launch_klms)
        #self.spawn(self.launch_agents)
        #self.spawn(self.launch_tests)
    #end do_start

    def do_reload(self):
        import pdb; pdb.set_trace()
    #end do_reload

    def do_stop(self):
        if self._keystone_server:
            self._keystone_server.kill()
        if self._ifmap_server:
            self._ifmap_server.kill()
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

        args_str = '--auth keystone %s %s %s %s %s %s' %(IFMAP_SVR_IP,
                                                         IFMAP_SVR_PORT,
                                                         IFMAP_SVR_USER,
                                                         IFMAP_SVR_PASSWD,
                                                         CASS_SVR_IP,
                                                         CASS_SVR_PORT)
        vnc_cfg_api_server.main(args_str)
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
                                               IFMAP_SVR_IP, IFMAP_SVR_PORT,
                                               IFMAP_SVR_USER2, IFMAP_SVR_PASSWD2,
                                               API_SVR_IP, API_SVR_PORT,
                                               ZK_SVR_IP, ZK_SVR_PORT],
                                              cwd = SCHEMA_TRANSFORMER_LOC)
        self._schema_transformer = schema_transformer
    #end launch_schema_transformer

    def launch_bgp_server(self):
        # Wait for IFMAP server to be running before launching bgp server 
        self._block_till_port_listened('ifmap-server', IFMAP_SVR_IP, IFMAP_SVR_PORT)

        logf_out = open('bgp-server.out', 'w')
        logf_err = open('bgp-server.err', 'w')
        bgp_server = subprocess.Popen(['./build/debug/control-node/control-node',
            '--map-server-url', 'https://%s:%s' %(IFMAP_SVR_IP, IFMAP_SVR_PORT),
            '--map-user', IFMAP_SVR_USER3, '--map-password', IFMAP_SVR_PASSWD3,
            '--bgp-port', BGP_SVR_PORT, '--sandesh-port', BGP_SANDESH_PORT],
            cwd = BGP_SVR_ROOT, env = {'LD_LIBRARY_PATH': '%s/build/lib' %(BGP_SVR_ROOT)},
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
