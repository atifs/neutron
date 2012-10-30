from ginkgo import Service

import eventlet
import os
import sys
sys.path.insert(0, os.getcwd())
from quantum.server import main as server
#eventlet.monkey_patch(thread=False)

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

IFMAP_SVR_IP = '127.0.0.1'
IFMAP_SVR_PORT = '8443'
IFMAP_SVR_USER = 'test'
IFMAP_SVR_PASSWD = 'test'
CASS_SVR_IP = '127.0.0.1'
CASS_SVR_PORT = '9160'
API_SVR_IP = '127.0.0.1'
API_SVR_PORT = '8082'
QUANTUM_SVR_IP = '127.0.0.1'
QUANTUM_SVR_PORT = '9595'

IFMAP_SVR_LOC='/home/contrail/irond-dist'
QUANTUM_SVR_LOC='/opt/stack/quantum/'

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
    #end setUp
        
    def test_network(self):
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

        with self.assertRaises(exceptions.QuantumClientException) as e:
            self._quantum.show_network(net_id)

        net_rsp = self._quantum.list_networks()
        self.assertFalse(net_name in [network['name'] \
                                     for network in net_rsp['networks']])
    #end test_network

    def test_subnet(self):
        # Create; Verify with show + list 
        net_obj = VirtualNetwork()
        net_rsp = self._quantum.create_network({'network': {'name': 'vn1'}})
        net_id = net_rsp['network']['id']
    #end test_subnet

#end class CRUDTestCase

class TestBench(Service):
    def __init__(self):
        self._ifmap_server = None
        self._quantum_server = None
    #end __init__

    def do_start(self):
        self.spawn(self.launch_ifmap_server)
        self.spawn(self.launch_api_server)
        self.spawn(self.launch_quantum_plugin)
        self.spawn(self.launch_unit_tests)
    #end do_start

    def do_reload(self):
        import pdb; pdb.set_trace()
    #end do_reload

    def do_stop(self):
        if self._ifmap_server:
            self._ifmap_server.kill()
        if self._quantum_server:
            self._quantum_server.kill()
    #end do_stop

    def launch_ifmap_server(self):
        maps = subprocess.Popen(['java', '-jar', 'build/irond.jar'],
                                cwd=IFMAP_SVR_LOC) 
        self._ifmap_server = maps
    #end launch_ifmap_server

    def launch_api_server(self):
        # Wait for IFMAP server to be running before launching api server
        self._block_till_port_listened('ifmap-server', IFMAP_SVR_IP, IFMAP_SVR_PORT)

        args_str = '%s %s %s %s %s %s' %(IFMAP_SVR_IP,
                                         IFMAP_SVR_PORT,
                                         IFMAP_SVR_USER,
                                         IFMAP_SVR_PASSWD,
                                         CASS_SVR_IP,
                                         CASS_SVR_PORT)
        vnc_cfg_api_server.main(args_str)
    #end launch_api_server

    def launch_quantum_plugin(self):
        # Wait for API server to be running before launching Q plugin
        self._block_till_port_listened('api-server', API_SVR_IP, API_SVR_PORT)

        quantum_server = subprocess.Popen([QUANTUM_SVR_LOC + '/bin/quantum-server',
                                           '--config-file=quantum.conf',
                                           '--config-file=contrail_plugin.ini'])
        self._quantum_server = quantum_server
    #end launch_quantum_plugin

    def launch_unit_tests(self):
        self._block_till_port_listened('quantum-server', QUANTUM_SVR_IP,
                                                         QUANTUM_SVR_PORT)
 
        del sys.argv[1:]
        suite1 = unittest.TestLoader().loadTestsFromTestCase(CRUDTestCase)
        #all_tests = unittest.TestSuite([suite1])
        #unittest.main(defaultTest=all_tests)
        unittest.TextTestRunner(verbosity=2).run(suite1)
    #end launch_unit_tests

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
