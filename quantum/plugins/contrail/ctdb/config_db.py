# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""
import requests
import re
import uuid
import json
import uuid
from netaddr import IPNetwork, IPSet, IPAddress

from quantum.common import constants
from vnc_api import *

_DEFAULT_HEADERS = {
                    'Content-type': 'application/json; charset="UTF-8"',
                   }

class DBInterface(object):
    """
    An instance of this class forwards requests to vnc cfg api (web)server
    """
    Q_URL_PREFIX = '/extensions/ct'
    def __init__(self, api_srvr_ip, api_srvr_port):
        self._api_srvr_ip = api_srvr_ip
	self._api_srvr_port = api_srvr_port

        # TODO remove hardcode
        self._vnc_lib = VncApi('user1', 'password1', 'default-domain',
                               api_srvr_ip, api_srvr_port, '/')

        self._subnet_map = {}
    #end __init__

    # Helper routines
    def _request_api_server(self, url, method, data = None, headers = None):
        if method == 'GET':
	    return requests.get(url)
        if method == 'POST':
            return requests.post(url, data = data, headers = headers)
        if method == 'DELETE':
	    return requests.delete(url)
    #end _request_api_server

    def _relay_request(self, request):
        """
        Send received request to api server
        """
	# chop quantum parts of url and add api server address
	url_path = re.sub(self.Q_URL_PREFIX, '', request.environ['PATH_INFO'])
	url = "http://%s:%s%s" %(self._api_srvr_ip, self._api_srvr_port,
	                         url_path)

        return self._request_api_server(
                        url, request.environ['REQUEST_METHOD'], request.body,
                        {'Content-type': request.environ['CONTENT_TYPE']})
    #end _relay_request

    def _ensure_project_exists(self, project_id):
        project_obj = Project(project_id)
        try:
            id = self._vnc_lib.fq_name_to_id(project_obj.get_fq_name())
        except NoIdError:
            # project doesn't exist, create it
            self._vnc_lib.project_create(project_obj)
    #end _ensure_project_exists

    def _ensure_vrouter_exists(self, vrouter_id):
        vrouter_name = "%s" %(vrouter_id)
        vrouter_obj = VirtualRouter(vrouter_name)
        try:
            id = self._vnc_lib.fq_name_to_id(vrouter_obj.get_fq_name())
        except NoIdError: # vrouter/server doesn't exist, create it
            self._vnc_lib.virtual_router_create(vrouter_obj)
    #end _ensure_vrouter_exists

    def _ensure_instance_exists(self, instance_id):
        instance_name = instance_id
        instance_obj = VirtualMachine(instance_name)
        try:
            id = self._vnc_lib.fq_name_to_id(instance_obj.get_fq_name())
        except NoIdError: # instance doesn't exist, create it
            self._vnc_lib.virtual_machine_create(instance_obj)
    #end _ensure_instance_exists

    # find projects on a given domain
    def _project_list_domain(self, domain_id):
        # TODO resolve domain_id vs domain_name
        domain_obj = Domain(domain_id)
        resp_str = self._vnc_lib.projects_list(domain_obj)
        resp_dict = json.loads(resp_str)

        return resp_dict['projects']
    #end _project_list_domain

    # find network ids on a given project
    def _network_list_project(self, project_id):
        # TODO resolve project_id vs project_name
        project_obj = Project(project_id)
        resp_str = self._vnc_lib.virtual_networks_list(project_obj)
        resp_dict = json.loads(resp_str)

        return resp_dict['virtual-networks']
    #end _network_list_project

    def _ipam_list_project(self, project_id):
        # TODO resolve project_id vs project_name
        project_obj = Project(project_id)
        resp_str = self._vnc_lib.network_ipams_list(project_obj)
        resp_dict = json.loads(resp_str)

        return resp_dict['network-ipams']
    #end _ipam_list_project

    # find port ids on a given network
    def _port_list_network(self, network_id):
        ret_list = []

        net_obj = self._vnc_lib.virtual_network_read(id = network_id)
        for port_back_ref in net_obj.get_virtual_machine_interface_back_refs():
            port_fq_name = port_back_ref['to']
            port_id = self._vnc_lib.fq_name_to_id(port_fq_name)
            port_obj = self._vnc_lib.virtual_machine_interface_read(id = port_id)
            ret_info = {}
            ret_info['id'] = port_obj.uuid
            ret_list.append(ret_info)

        return ret_list
    #end _port_list_network

    # find port ids on a given project
    def _port_list_project(self, project_id):
        ret_list = []
        project_nets = self._network_list_project(project_id)
        for net in project_nets:
            net_ports = self._port_list_network(net['uuid'])
            ret_list.extend(net_ports)

        return ret_list
    #end _port_list_project

    # Returns True if 
    #     * no filter is specified
    #     OR
    #     * search-param is not present in filters
    #     OR
    #     * 1. search-param is present in filters AND
    #       2. resource matches param-list AND
    #       3. shared parameter in filters is False
    def _filters_is_present(self, filters, key_name, match_value):
        if filters and filters.has_key(key_name):
            try:
                idx = filters[key_name].index(match_value)
                if (filters.has_key('shared') and
                    filters['shared'][idx] == True):
                    return False # no shared-subnet support
            except ValueError: # not in requested list
                return False

        return True
    #end _filters_is_present

    def _network_read(self, net_uuid):
        net_obj = self._vnc_lib.virtual_network_read(id = net_uuid)
        return net_obj
    #end _network_read

    def _subnet_vnc_create_mapping(self, subnet_id, subnet_key):
        self._vnc_lib.kv_store(subnet_id, subnet_key)
        self._vnc_lib.kv_store(subnet_key, subnet_id)
    #end _subnet_vnc_create_mapping

    def _subnet_vnc_read_mapping(self, id = None, key = None):
        if id:
            return self._vnc_lib.kv_retrieve(id)
        if key:
            return self._vnc_lib.kv_retrieve(key)
    #end _subnet_vnc_read_mapping

    def _subnet_vnc_delete_mapping(self, subnet_id, subnet_key):
        self._vnc_lib.kv_delete(subnet_id)
        self._vnc_lib.kv_delete(subnet_key)
    #end _subnet_vnc_delete_mapping

    def _subnet_vnc_get_key(self, subnet_vnc, net_obj):
        pfx = subnet_vnc.get_ip_prefix()
        pfx_len = subnet_vnc.get_ip_prefix_len()
        fq_name_str = ':'.join(net_obj.get_fq_name())

        return '%s %s/%s' %(fq_name_str, pfx, pfx_len)
    #end _subnet_vnc_get_key

    def _ip_address_to_subnet_id(self, ip_addr, net_obj):
        for ipam_ref in net_obj.get_network_ipam_refs():
            subnets = ipam_ref['attr'].get_subnet()
            for subnet_vnc in subnets:
                cidr = '%s/%s' %(subnet_vnc.get_ip_prefix(),
                                 subnet_vnc.get_ip_prefix_len())
                if IPAddress(ip_addr) in IPSet([cidr]):
                    subnet_key = self._subnet_vnc_get_key(subnet_vnc, net_obj)
                    subnet_id = self._subnet_vnc_read_mapping(key = subnet_key)
                    return subnet_id

        return None
    #end _ip_address_to_subnet_id

    # Conversion routines between VNC and Quantum objects
    def _network_quantum_to_vnc(self, network_q):
        net_name = network_q['name']
        project_id = network_q['tenant_id']
        project_obj = Project(project_id)
        net_obj = VirtualNetwork(net_name, project_obj)

        return net_obj
    #end _network_quantum_to_vnc

    def _network_vnc_to_quantum(self, net_obj):
        net_q_dict = {}
        extra_dict = {}

        net_q_dict['id'] = net_obj.uuid
        net_q_dict['name'] = net_obj.name
        # TODO resolve name/id for projects
        net_q_dict['tenant_id'] = net_obj.parent_name
        # TODO fix-me
        net_q_dict['admin_state_up'] = True
        net_q_dict['shared'] = False
        net_q_dict['status'] = constants.NET_STATUS_ACTIVE

        net_q_dict['ports'] = []
        for port_back_ref in net_obj.get_virtual_machine_interface_back_refs():
            fq_name = port_back_ref['to']
            port_obj = self._vnc_lib.virtual_machine_interface_read(id = fq_name[-1])

            port_info = self._port_vnc_to_quantum(port_obj)
            port_dict = port_info['q_api_data']
            port_dict.update(port_info['q_extra_data'])

            net_q_dict['ports'].append(port_dict)

        net_q_dict['subnets'] = []
        extra_dict['contrail:subnet_ipam'] = []
        for ipam_ref in net_obj.get_network_ipam_refs():
            subnets = ipam_ref['attr'].get_subnet()
            for subnet in subnets:
                sn_info = self._subnet_vnc_to_quantum(subnet, net_obj,
                                                      ipam_ref['to'])
                sn_dict = sn_info['q_api_data']
                sn_dict.update(sn_info['q_extra_data'])
                net_q_dict['subnets'].append(sn_dict)
                sn_ipam = {}
                sn_ipam['subnet_cidr'] = sn_dict['cidr']
                sn_ipam['ipam_fq_name'] = ipam_ref['to']
                extra_dict['contrail:subnet_ipam'].append(sn_ipam)

        # TODO determine right values
        extra_dict['contrail:instance_count'] = 0
        net_policy_refs = net_obj.get_network_policy_refs()
        if net_policy_refs:
            extra_dict['contrail:policy'] = net_policy_refs[0]['to']

        return {'q_api_data': net_q_dict,
                'q_extra_data': extra_dict}
    #end _network_vnc_to_quantum

    def _subnet_quantum_to_vnc(self, subnet_q):
        cidr = subnet_q['cidr'].split('/')
        pfx = cidr[0]
        pfx_len = int(cidr[1])
        subnet_vnc = SubnetType(pfx, pfx_len)

        return subnet_vnc
    #end _subnet_quantum_to_vnc

    def _subnet_vnc_to_quantum(self, subnet_vnc, net_obj, ipam_fq_name):
        sn_q_dict = {}
        sn_q_dict['name'] = ''
        # TODO resolve tenant_id/tenant_name with keystone sync-up on boot
        sn_q_dict['tenant_id'] = net_obj.parent_name
        sn_q_dict['network_id'] = net_obj.uuid
        sn_q_dict['ip_version'] = 4 #TODO ipv6?

        cidr = '%s/%s' %(subnet_vnc.get_ip_prefix(),
                         subnet_vnc.get_ip_prefix_len())
        sn_q_dict['cidr'] = cidr

        subnet_key = self._subnet_vnc_get_key(subnet_vnc, net_obj)
        sn_id = self._subnet_vnc_read_mapping(key = subnet_key)
        sn_q_dict['id'] = sn_id

        sn_q_dict['gateway_ip'] = '169.254.169.254'

        first_ip = str(IPNetwork(cidr).network + 1)
        last_ip = str(IPNetwork(cidr).broadcast - 1)
        sn_q_dict['allocation_pools'] = \
            [{'id': 'TODO-allocation_pools-id',
             'subnet_id': sn_id,
             'first_ip': first_ip, 
             'last_ip': last_ip, 
             'available_ranges': {}
            }]

        # TODO get from ipam_obj
        sn_q_dict['enable_dhcp'] = False 
        sn_q_dict['dns_nameservers'] = [{'address': '169.254.169.254',
                                        'subnet_id': sn_id}]

        sn_q_dict['routes'] = [{'destination': 'TODO-destination',
                               'nexthop': 'TODO-nexthop',
                               'subnet_id': sn_id
                              }]

        sn_q_dict['shared'] = False

        extra_dict = {}
        extra_dict['contrail:instance_count'] = 0
        extra_dict['contrail:ipam_fq_name'] = ':'.join(ipam_fq_name)

        return {'q_api_data': sn_q_dict,
                'q_extra_data': extra_dict}
    #end _subnet_vnc_to_quantum

    def _ipam_quantum_to_vnc(self, ipam_q):
        ipam_name = ipam_q['name']
        project_id = ipam_q['tenant_id']
        project_obj = Project(project_id)

        options_obj = DhcpOptionsListType()
        for opt_q in ipam_q['mgmt'].get('options', []):
            options_obj.add_dhcp_option(DhcpOptionType(opt_q['option'],
                                                       opt_q['value']))
        ipam_mgmt_obj = IpamType.factory(ipam_method = ipam_q['mgmt']['method'],
                                         dhcp_option_list = options_obj)

        ipam_obj = NetworkIpam(ipam_name, project_obj, ipam_mgmt_obj)

        return ipam_obj
    #end _ipam_quantum_to_vnc

    def _ipam_vnc_to_quantum(self, ipam_obj):
        ipam_q_dict = {}
        ipam_q_dict['id'] = ipam_obj.uuid
        ipam_q_dict['name'] = ipam_obj.name
        ipam_q_dict['tenant_id'] = ipam_obj.parent_name
        ipam_q_dict['mgmt'] = {}
        ipam_mgmt_obj = ipam_obj.get_network_ipam_mgmt()
        if ipam_mgmt_obj:
            ipam_q_dict['mgmt']['method'] = ipam_mgmt_obj.get_ipam_method()
            ipam_q_dict['mgmt']['options'] = []
            options_obj = ipam_mgmt_obj.get_dhcp_option_list()
            for opt_obj in options_obj.get_dhcp_option():
                opt_q = {}
                opt_q['option'] = opt_obj.get_dhcp_option_name()
                opt_q['value'] = opt_obj.get_dhcp_option_value()
                ipam_q_dict['mgmt']['options'].append(opt_q)

        return {'q_api_data': ipam_q_dict,
                'q_extra_data': {}}
    #end _ipam_vnc_to_quantum

    def _port_quantum_to_vnc(self, port_q, net_obj = None):
        if not net_obj:
            net_id = port_q['network_id']
            net_obj = self._network_read(net_id)
            
        port_name = str(uuid.uuid4())
        instance_name = port_q['device_id']
        instance_obj = VirtualMachine(instance_name)
        port_obj = VirtualMachineInterface(port_name, instance_obj)
        port_obj.set_virtual_network(net_obj)

        return port_obj
    #end _port_quantum_to_vnc

    def _port_vnc_to_quantum(self, port_obj):
        port_q_dict = {}
        port_q_dict['name'] = port_obj.uuid
        port_q_dict['id'] = port_obj.uuid

        net_fq_name = port_obj.get_virtual_network_refs()[0]['to']
        # TODO read obj directly from fq_name once lib supports
        net_id = self._vnc_lib.fq_name_to_id(net_fq_name)
        net_obj = self._vnc_lib.virtual_network_read(id = net_id)
        port_q_dict['tenant_id'] = net_obj.parent_name
        port_q_dict['network_id'] = net_obj.uuid

        # TODO RHS below may need fixing
        port_q_dict['mac_address'] = \
           port_obj.get_virtual_machine_interface_mac_addresses().mac_address[0]

        port_q_dict['fixed_ips'] = []
        for ip_back_ref in port_obj.get_instance_ip_back_refs():
            ip_fq_name = ip_back_ref['to']
            ip_obj = self._vnc_lib.instance_ip_read(id = ip_fq_name[-1])
            ip_addr = ip_obj.get_instance_ip_address()

            ip_q_dict = {}
            ip_q_dict['port_id'] = port_obj.uuid
            ip_q_dict['ip_address'] = ip_addr
            ip_q_dict['subnet_id'] = self._ip_address_to_subnet_id(ip_addr,
                                                                   net_obj)
            ip_q_dict['net_id'] = net_id

            port_q_dict['fixed_ips'].append(ip_q_dict)

        port_q_dict['admin_state_up'] = True
        port_q_dict['status'] = constants.PORT_STATUS_ACTIVE
        port_q_dict['device_id'] = port_obj.parent_name
        port_q_dict['device_owner'] = 'TODO-device-owner'

        return {'q_api_data': port_q_dict,
                'q_extra_data': {}}
    #end _port_vnc_to_quantum

    # public methods
    # network api handlers
    def network_create(self, network_q):
        # TODO remove below once api-server can read and create projects
        # from keystone on startup
        self._ensure_project_exists(network_q['tenant_id'])
       
        net_obj = self._network_quantum_to_vnc(network_q)
        net_uuid = self._vnc_lib.virtual_network_create(net_obj)

        return self._network_vnc_to_quantum(net_obj)
    #end network_create

    def network_read(self, net_uuid):
        net_obj = self._network_read(net_uuid)

        return self._network_vnc_to_quantum(net_obj)
    #end network_read

    #def network_update(self, net_id, net_dict):
    ##end network_update

    def network_delete(self, net_id):
        self._vnc_lib.virtual_network_delete(id = net_id)
    #end network_delete

    # TODO request based on filter contents
    def network_list(self, filters = None):
        ret_list = []

        # collect phase
        all_nets = [] # all n/ws in all projects
        if filters and filters.has_key('tenant_id'):
            project_ids = filters['tenant_id']
            for p_id in project_ids:
                project_nets = self._network_list_project(p_id)
                all_nets.append(project_nets)
        else: # no filters
            dom_projects = self._project_list_domain(None)
            for project in dom_projects:
                project_nets = self._network_list_project(project['name'])
                all_nets.append(project_nets)

        # prune phase
        for project_nets in all_nets:
            for proj_net in project_nets:
                # TODO implement same for name specified in filter
                proj_net_id = proj_net['uuid']
                if not self._filters_is_present(filters, 'id', proj_net_id):
                    continue
                net_info = self.network_read(proj_net['uuid'])
                ret_list.append(net_info)

        return ret_list
    #end network_list

    # subnet api handlers
    def subnet_create(self, subnet_q):
        net_id = subnet_q['network_id']
        net_obj = self._vnc_lib.virtual_network_read(id = net_id)

        if subnet_q['contrail:ipam_fq_name'] != '':
            ipam_fq_name = subnet_q['contrail:ipam_fq_name'].split(':')
            domain_name = ipam_fq_name[0]
            project_name = ipam_fq_name[1]
            ipam_name = ipam_fq_name[2]

            domain_obj = Domain(domain_name)
            project_obj = Project(project_name, domain_obj)
            netipam_obj = NetworkIpam(ipam_name, project_obj)
        else: # link subnet with default ipam
            project_obj = Project(subnet_q['tenant_id'])
            netipam_obj = NetworkIpam(project = project_obj)
            ipam_fq_name = netipam_obj.get_fq_name()

        subnet_vnc = self._subnet_quantum_to_vnc(subnet_q)

        # Locate list of subnets to which this subnet has to be appended
        net_ipam_ref = None
        for ipam_ref in net_obj.get_network_ipam_refs():
            if ipam_ref['to'] == ipam_fq_name:
                net_ipam_ref = ipam_ref
                break

        if not net_ipam_ref:
            # First link from net to this ipam
            vnsn_data = VnSubnetsType([subnet_vnc])
            net_obj.add_network_ipam(netipam_obj, vnsn_data)
        else: # virtual-network already linked to this ipam
            vnsn_data = net_ipam_ref['attr']
            vnsn_data.subnet.append(subnet_vnc)
            net_obj.set_network_ipam(netipam_obj, vnsn_data)

        self._vnc_lib.virtual_network_update(net_obj)

        # allocate an id to the subnet and store mapping with
        # api-server
        subnet_id = str(uuid.uuid4())
        subnet_key = self._subnet_vnc_get_key(subnet_vnc, net_obj)
        self._subnet_vnc_create_mapping(subnet_id, subnet_key)

        subnet_info = self._subnet_vnc_to_quantum(subnet_vnc, net_obj,
                                                  ipam_fq_name)

        return subnet_info
    #end subnet_create

    def subnet_read(self, subnet_id):
        subnet_key = self._subnet_vnc_read_mapping(id = subnet_id)
        net_fq_name_str = subnet_key.split()[0]
        net_fq_name = net_fq_name_str.split(':')

        net_id = self._vnc_lib.fq_name_to_id(net_fq_name)
        net_obj = self._network_read(net_id)
        for ipam_ref in net_obj.get_network_ipam_refs():
            subnets = ipam_ref['attr'].get_subnet()
            for subnet_vnc in subnets:
                if self._subnet_vnc_get_key(subnet_vnc, net_obj) == subnet_key:
                    return self._subnet_vnc_to_quantum(subnet_vnc, net_obj,
                                                       ipam_ref['to'])

        return {}
    #end subnet_read

    def subnet_update(self, subnet_id, subnet_q):
        # TODO implement this
        return subnet_q
    #end subnet_update

    def subnet_delete(self, subnet_id):
        subnet_key = self._subnet_vnc_read_mapping(id = subnet_id)
        net_fq_name_str = subnet_key.split()[0]
        net_fq_name = net_fq_name_str.split(':')

        net_id = self._vnc_lib.fq_name_to_id(net_fq_name)
        net_obj = self._network_read(net_id)
        for ipam_ref in net_obj.get_network_ipam_refs():
            orig_subnets = ipam_ref['attr'].get_subnet()
            new_subnets = [subnet for subnet in orig_subnets \
                           if self._subnet_vnc_get_key(subnet, net_obj) != subnet_key]
            if len(orig_subnets) != len(new_subnets):
                # matched subnet to be deleted
                ipam_ref['attr'].set_subnet(new_subnets)
                self._vnc_lib.virtual_network_update(net_obj)
                self._subnet_vnc_delete_mapping(subnet_id, subnet_key)
                return
    #end subnet_delete

    def subnets_list(self, filters = None):
        ret_subnets = []

        # TODO refactor to query based on filter values
        nets_info = self.network_list()
        for n_info in nets_info:
            net_obj = self._network_read(n_info['q_api_data']['id'])
            for ipam_ref in net_obj.get_network_ipam_refs():
                subnets = ipam_ref['attr'].get_subnet()
                for subnet in subnets:
                    sn_info = self._subnet_vnc_to_quantum(subnet, net_obj,
                                                          ipam_ref['to'])
                    sn_id = sn_info['q_api_data']['id']
                    sn_proj_id = sn_info['q_api_data']['tenant_id']
                    sn_net_id = sn_info['q_api_data']['network_id']

                    if filters:
                        if not self._filters_is_present(filters, 'id', sn_id):
                            continue
                        if not self._filters_is_present(filters, 'tenant_id',
                                                        sn_proj_id):
                            continue
                        if not self._filters_is_present(filters, 'network_id',
                                                        sn_net_id):
                            continue

                    ret_subnets.append(sn_info)

        return ret_subnets
    #end subnets_list

    # ipam api handlers
    def ipam_create(self, ipam_q):
        # TODO remove below once api-server can read and create projects
        # from keystone on startup
        self._ensure_project_exists(ipam_q['tenant_id'])

        ipam_obj = self._ipam_quantum_to_vnc(ipam_q)
        ipam_uuid = self._vnc_lib.network_ipam_create(ipam_obj)

        return self._ipam_vnc_to_quantum(ipam_obj)
    #end ipam_create

    def ipam_read(self, ipam_id):
        ipam_obj = self._vnc_lib.network_ipam_read(id = ipam_id)

        return self._ipam_vnc_to_quantum(ipam_obj)
    #end ipam_read

    #def ipam_update(self, ipam_id, ipam_q):
    ##end ipam_update

    #def ipam_delete(self, ipam_id):
    ##end ipam_delete

    # TODO request based on filter contents
    def ipam_list(self, filters = None):
        ret_list = []

        # collect phase
        all_ipams = [] # all ipams in all projects
        if filters and filters.has_key('tenant_id'):
            project_ids = filters['tenant_id']
            for p_id in project_ids:
                project_ipams = self._ipam_list_project(p_id)
                all_ipams.append(project_ipams)
        else: # no filters
            dom_projects = self._project_list_domain(None)
            for project in dom_projects:
                project_ipams = self._ipam_list_project(project['name'])
                all_ipams.append(project_ipams)

        # prune phase
        for project_ipams in all_ipams:
            for proj_ipam in project_ipams:
                # TODO implement same for name specified in filter
                proj_ipam_id = proj_ipam['uuid']
                if not self._filters_is_present(filters, 'id', proj_ipam_id):
                    continue
                ipam_info = self.ipam_read(proj_ipam['uuid'])
                ret_list.append(ipam_info)

        return ret_list
    #end ipam_list

    # port api handlers
    def port_create(self, port_q):
        # TODO check for duplicate add and return
        net_id = port_q['network_id']
        net_obj = self._network_read(net_id)

        self._ensure_vrouter_exists(port_q['compute_node_id'])
        self._ensure_instance_exists(port_q['device_id'])


        # initialize port object
        port_obj = self._port_quantum_to_vnc(port_q, net_obj)

        # initialize ip object
        ip_name = str(uuid.uuid4())
        ip_obj = InstanceIp(name = ip_name)
        ip_obj.set_virtual_machine_interface(port_obj)
        ip_obj.set_virtual_network(net_obj)

        # create the objects
        port_id = self._vnc_lib.virtual_machine_interface_create(port_obj)
        ip_id = self._vnc_lib.instance_ip_create(ip_obj)

        # read back the allocated ip address
        ip_obj = self._vnc_lib.instance_ip_read(id = ip_id)
        ip_addr = ip_obj.get_instance_ip_address()
        sn_id = self._ip_address_to_subnet_id(ip_addr, net_obj)
        fixed_ips =  [{'ip_address': '%s' %(ip_addr), 'subnet_id': sn_id}]

        # TODO below reads back default parent name, fix it
        port_obj = self._vnc_lib.virtual_machine_interface_read(id = port_id)

        return self._port_vnc_to_quantum(port_obj)
    #end port_create

    # TODO add obj param and let caller use below only as a converter
    def port_read(self, context, id, fields = None):
        port_obj = self._vnc_lib.virtual_machine_interface_read(id = id)

        return self._port_vnc_to_quantum(port_obj)
    #end port_read

    def port_list(self, filters = None):
        project_obj = None
        ret_q_ports = []

        # TODO used to find dhcp server field. support later...
        if filters.has_key('device_owner'):
            return ret_q_ports

        if not filters.has_key('device_id'):
            # Listing from back references
            for proj_id in filters.get('tenant_id', []):
                proj_ports = self._port_list_project(proj_id)
                for port in proj_ports:
                    port_info = self.port_read(None, port['id'])
                    ret_q_ports.append(port_info)

            for net_id in filters.get('network_id', []):
                net_ports = self._port_list_network(net_id)
                for port in net_ports:
                    port_info = self.port_read(None, port['id'])
                    ret_q_ports.append(port_info)

            return ret_q_ports

        # Listing from parent to children
        virtual_machine_ids = filters['device_id']
        for vm_id in virtual_machine_ids:
            try:
                vm_obj = self._vnc_lib.virtual_machine_read(id = vm_id)
            except NoIdError:
                continue
            resp_str = self._vnc_lib.virtual_machine_interfaces_list(vm_obj)
            resp_dict = json.loads(resp_str)
            vm_intf_ids = resp_dict['virtual-machine-interfaces']
            for vm_intf in vm_intf_ids:
                port_info = self.port_read(None, vm_intf['uuid'])
                ret_q_ports.append(port_info)

        return ret_q_ports
    #end port_list

#end class DBInterface
