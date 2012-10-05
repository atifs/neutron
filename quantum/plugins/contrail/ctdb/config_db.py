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
from netaddr import IPAddress

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
        self._vnc_lib = VncApi('user1', 'password1', 'default-tenant',
                               api_srvr_ip, api_srvr_port, '/')

        # TODO move this to db_cache class
        self._db_cache = {}
        self._db_cache['tenants'] = {'infra': {'vpc_ids':set([])} }
        self._db_cache['vpcs'] = {}
        self._db_cache['vns'] = {}
        self._db_cache['instances'] = {}
        self._db_cache['ports'] = {}
        self._db_cache['subnets'] = {}

    def _request_api_server(self, url, method, data = None, headers = None):
        if method == 'GET':
	    return requests.get(url)
        if method == 'POST':
            return requests.post(url, data = data, headers = headers)
        if method == 'DELETE':
	    return requests.delete(url)

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

    def vpc_create(self, request):
	rsp = self._relay_request(request)
        if rsp.status_code == 200:
            tenant = self._db_cache['tenants']['infra']
            vpc_id = json.loads(rsp.text)['vpc']['vpc-id']
            self._db_cache['vpcs'][vpc_id] = {'vn_ids': set([])}
            tenant['vpc_ids'].add(vpc_id)
        return rsp

    def vpc_get(self, request):
	rsp = self._relay_request(request)
	return rsp

    def vpc_delete(self, request):
	rsp = self._relay_request(request)
	return rsp

    def vn_create(self, request):
	rsp = self._relay_request(request)
        if rsp.status_code == 200:
            vpc_id = json.loads(request.body)['vn']['vn_vpc_id']
            vpc = self._db_cache['vpcs'][vpc_id]
            vn_id = json.loads(rsp.text)['vn']['vn-id']
            self._db_cache['vns'][vn_id] = {'instance_ids':set([])}
            vpc['vn_ids'].add(vn_id)
	return rsp

    def vn_get(self, request):
	rsp = self._relay_request(request)
	return rsp

    def vn_delete(self, request):
	rsp = self._relay_request(request)
	return rsp

    def network_create(self, project_id, name):
        project_obj = NetworkGroup(project_id)
        # TODO remove below once api-server can read and create projects
        # from keystone on startup
        try:
            id = self._vnc_lib.fq_name_to_id(project_obj.get_fq_name())
        except NoIdError:
            # project doesn't exist, create it
            self._vnc_lib.network_group_create(project_obj)

        net_obj = VirtualNetwork(name, project_obj)
        net_uuid = self._vnc_lib.virtual_network_create(net_obj)

        return net_uuid
    #end network_create

    def _network_read(self, net_uuid):
        net_obj = self._vnc_lib.virtual_network_read(id = net_uuid)
        return net_obj
    #end _network_read

    def network_read(self, net_uuid):
        net_obj = self._network_read(net_uuid)
        ret_dict = {}
        ret_dict['id'] = net_obj.uuid
        ret_dict['name'] = net_obj.name
        # TODO resolve name/id for projects
        ret_dict['tenant_id'] = net_obj.parent_name

        return ret_dict
    #end network_read

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
            for net_info in project_nets:
                # TODO implement same for name specified in filter
                if (filters and filters.has_key('id')):
                    # if net_info not in requested networks, ignore
                    if not net_info['uuid'] in filters['id']:
                        continue
                    else: # net_info present in filters
                        if filters.has_key('shared'):
                            net_idx = filters['id'].index(net_info['uuid'])
                            shared = filters['shared'][net_idx]
                            # if net_info in requested networks but request is
                            # for shared network, ignore
                            if shared:
                                continue

                net_dict = self.network_read(net_info['uuid'])
                r_info = {}
                r_info['id'] = net_info['uuid']
                import pdb; pdb.set_trace()
                r_info['tenant_id'] = net_dict['tenant_id']
                r_info['name'] = net_info['name']
                ret_list.append(r_info)

        return ret_list
    #end network_list

    #def network_list(self, filters = None):
    #    project_obj = None
    #    ret_list = []
    #    if filters and filters.has_key('tenant_id'):
    #        # TODO support more than one project
    #        project_id = filters['tenant_id'][0]
    #        project_obj = NetworkGroup(project_id)

    #    resp_str = self._vnc_lib.virtual_networks_list(project_obj)
    #    resp_dict = json.loads(resp_str)

    #    for net_info in resp_dict['virtual-networks']:
    #        if (filters and filters.has_key('id') and 
    #            not net_info['uuid'] in filters['id']):
    #            continue
    #        r_info = {}
    #        r_info['id'] = net_info['uuid']
    #        r_info['name'] = net_info['name']
    #        ret_list.append(r_info)

    #    return ret_list
    ##end network_list

    def subnet_create(self, subnet):
        net_id = subnet['subnet']['network_id']
        net_obj = self._vnc_lib.virtual_network_read(id = net_id)

        project_obj = NetworkGroup(subnet['subnet']['tenant_id'])
        netipam_obj = NetworkIpam(network_group = project_obj)

        cidr = subnet['subnet']['cidr'].split('/')
        pfx = cidr[0]
        pfx_len = int(cidr[1])

        net_ipam_refs = net_obj.get_network_ipam_refs()
        if not net_ipam_refs:
            vnsn_data = VnSubnetsType([SubnetType(pfx, pfx_len)])
            net_obj.add_network_ipam(netipam_obj, vnsn_data)
        else: # virtual-network already linked to ipam
            # TODO if support for multiple ipams refs is added,
            # below needs to change
            vnsn_data = net_ipam_refs[0][1]
            vnsn_data.subnet.append(SubnetType(pfx, pfx_len))
            net_obj.set_network_ipam(netipam_obj, vnsn_data)

        resp_str = self._vnc_lib.virtual_network_update(net_obj)
        return resp_str
    #end subnet_create

    def subnets_set(self, request):
        rsp = self._relay_request(request)
	return rsp

    def subnets_get_vnc(self, request):
        rsp = self._relay_request(request)
	return rsp

    def subnets_read(self, filters = None):
        ret_subnets = []

        networks = self.network_list(filters)
        for network in networks:
            net_obj = self._network_read(network['id'])

            for ipam_ref in net_obj.get_network_ipam_refs():
                subnets = ipam_ref['attr'].get_subnet()
                for subnet in subnets:
                    sn_info = {}
                    sn_info['cidr'] = '%s/%s' %(subnet.get_ip_prefix(),
                                                subnet.get_ip_prefix_len())
                    sn_info['network_id'] = net_obj.uuid
                    # TODO put some well-known address below?
                    sn_info['gateway_ip'] = '%s' %(subnet.get_ip_prefix())
                    ret_subnets.append(sn_info)

        #for subnet_id in subnet_ids:
        #    (vn_id, ip_addr) = self._db_cache['subnets'][subnet_id]
        #    # TODO query api-server to find ipam info for vn,ip pair
        #    subnet = {}
        #    subnet['cidr'] = ip_addr
        #    subnet['gateway_ip'] = str((IPAddress(ip_addr) &
        #                                IPAddress('255.255.255.0')) |
        #                               IPAddress('0.0.0.254'))
        #    ret_subnets.append(subnet)

        return ret_subnets
        
        
    def security_group_create(self, request):
	rsp = self._relay_request(request)
	return rsp

    def policy_create(self, request):
	rsp = self._relay_request(request)
	return rsp

    def policy_entry_list_create(self, request, tenant_uuid, pol_id, pe_list):
        pass

    def _instance_create(self, tenant_id, vn_id, instance_id):
        url_path = "/tenants/%s/instance" %(tenant_id)
        dict_param = {'instance_id': instance_id,
                      'vn_id': vn_id}
        json_param = json.dumps(dict_param)
        json_body = '{"instance":' + json_param + '}'

	url = "http://%s:%s%s" %(self._api_srvr_ip, self._api_srvr_port,
	                         url_path)
        rsp = self._request_api_server(url, 'POST', json_body, _DEFAULT_HEADERS)
        return rsp

    def _port_create(self, tenant_id, vn_id, instance_id):
        url_path = "/tenants/%s/port" %(tenant_id)
        # TODO hints may have to be passed from quantum for alloc param
        addr_param = {'ip_alloc': True,
                      'mac_alloc': True}
        dict_param = {'vn_id': vn_id,
                      'instance_id': instance_id,
                      'addr_param': addr_param}
        json_param = json.dumps(dict_param)
        json_body = '{"port":' + json_param + '}'

	url = "http://%s:%s%s" %(self._api_srvr_ip, self._api_srvr_port,
	                         url_path)
        rsp = self._request_api_server(url, 'POST', json_body, _DEFAULT_HEADERS)
        return rsp

    def port_create(self, port):
        ret_port = port

        # TODO check for duplicate add and return
        project_id = port['tenant_id']
        net_id = port['network_id']
        instance_id = port['device_id']
        server_id = port['compute_node_id']

        server_name = "server-%s" %(server_id)
        server_obj = VirtualRouterSwitch(server_name)
        try:
            id = self._vnc_lib.fq_name_to_id(server_obj.get_fq_name())
        except NoIdError: # vnsw/server doesn't exist, create it
            self._vnc_lib.virtual_router_switch_create(server_obj)

        instance_name = instance_id
        instance_obj = VirtualMachine(instance_name)
        try:
            id = self._vnc_lib.fq_name_to_id(instance_obj.get_fq_name())
        except NoIdError: # instance doesn't exist, create it
            self._vnc_lib.virtual_machine_create(instance_obj)

        net_obj = self._network_read(net_id)

        # initialize port object
        port_name = str(uuid.uuid4())
        port_obj = VirtualMachinePort(port_name, instance_obj)
        port_obj.set_virtual_network(net_obj)

        # initialize ip object
        ip_name = str(uuid.uuid4())
        ip_obj = InstanceIp(name = ip_name)
        ip_obj.set_virtual_machine_port(port_obj)
        ip_obj.set_virtual_network(net_obj)

        # create the objects
        port_id = self._vnc_lib.virtual_machine_port_create(port_obj)
        self._vnc_lib.instance_ip_create(ip_obj)

        ip_addr = ip_obj.get_instance_ip_address()
        fixed_ips =  [{'ip_address': '%s' %(ip_addr), 'subnet_id': net_id}]

        # TODO below reads back default parent name, fix it
        port_obj = self._vnc_lib.virtual_machine_port_read(id = port_id)
        ret_port['id'] = port_id
        # TODO RHS below may need fixing
        ret_port['mac_address'] = \
                port_obj.get_virtual_machine_port_mac_addresses().mac_address[0]
        ret_port['fixed_ips'] = fixed_ips

        return ret_port

        ## Create instance in oper-db if not already done
        #if not self._db_cache['instances'].has_key(instance_id):
        #    rsp = self._instance_create(tenant_id, vn_id, instance_id)
        #    if rsp.status_code == 200:
        #        self._db_cache['instances'][instance_id] = {'port_ids': set([])}
        #        self._db_cache['vns'][vn_id]['instance_ids'].add(instance_id)
        #    else:
        #        raise Exception("OperDB create instance failed: %s:%s" \
        #                        %(rsp.status_code, rsp.text))
      
        # Create port in oper-db
        #rsp = self._port_create(tenant_id, vn_id, instance_id)
        #if rsp.status_code == 200:
        #    rsp_port = json.loads(rsp.text)['port']
        #    # 'rsp_port' has vnc canonical port info. convert into
        #    # 'new_port' which is quantum canonical form and store in cache.
        #    # port_list() will pick from cache and send back this info
        ##    port_id = rsp_port['port-id']
        #    port_macs = rsp_port['port-macs']
        #    port_ips = rsp_port['port-ips']

        #    new_port['id'] = rsp_port['port-id']
        #    new_port['mac_address'] = rsp_port['port-macs'][0]
        #    # TODO is this enough for subnet_id?
        #    fixed_ips =  \
        #        [{'ip_address': '%s' %(ipa),
        #         'subnet_id': '%s %s' %(port_id, ipa)} for ipa in port_ips]
        #    new_port['fixed_ips'] = fixed_ips

        #    for fip in fixed_ips:
        #        # remember vn a subnet was assigned from
        #        self._db_cache['subnets'][fip['subnet_id']] = \
        #                                 (vn_id, fip['ip_address'])
        #    self._db_cache['ports'][port_id] = new_port
        #    self._db_cache['instances'][instance_id]['port_ids'].add(port_id)
        #else:
        #    raise Exception("OperDB create port failed: %s:%s" \
        #                    %(rsp.status_code, rsp.text))

        #return new_port

    def port_list(self, filters = None, detailed = False):
        project_obj = None
        ret_ports = []

        # TODO used to find dhcp server field. support later...
        if filters.has_key('device_owner'):
            return ret_ports

        if not filters.has_key('device_id'):
            # Listing from back references
            for proj_id in filters['tenant_id']:
                proj_ports = self._port_list_project(proj_id)
                ret_ports.extend(proj_ports)
            return ret_ports

        # Listing from parent to children
        virtual_machine_ids = filters['device_id']
        for vm_id in virtual_machine_ids:
            try:
                vm_obj = self._vnc_lib.virtual_machine_read(id = vm_id)
            except NoIdError:
                continue
            resp_str = self._vnc_lib.virtual_machine_ports_list(vm_obj)
            resp_dict = json.loads(resp_str)
            ret_ports.extend(resp_dict['virtual-machine-ports'])

        # grab/set additional details for the list of ports
        for port_info in ret_ports:
            import pdb; pdb.set_trace()
            port_id = port_info['uuid']
            port_info['id'] = port_id
            port_obj = self._vnc_lib.virtual_machine_port_read(id = port_id)
            # TODO fix RHS
            port_info['mac_address'] = \
                port_obj.get_virtual_machine_port_mac_addresses().mac_address[0]

            net_fq_name = port_obj.get_virtual_network_refs()[0]['to']
            net_id = self._vnc_lib.fq_name_to_id(net_fq_name)
            port_info['network_id'] = net_id

            port_info['fixed_ips'] = []
            for ip_back_ref in port_obj.get_instance_ip_back_refs():
                ip_fq_name = ip_back_ref['to']
                # ip_id == ip_fq_name could have been assumed
                ip_id = self._vnc_lib.fq_name_to_id(ip_fq_name)
                ip_obj = self._vnc_lib.instance_ip_read(id = ip_id)
                ip_addr = ip_obj.get_instance_ip_address().get_ip_address()

                ip_info = {}
                ip_info['ip_address'] = ip_addr
                # instance-ip will always be on port's vn
                ip_info['subnet_id'] = net_id
                port_info['fixed_ips'].append(ip_info)

        return ret_ports
    #end port_list

    # find projects on a given domain
    def _project_list_domain(self, domain_id):
        # TODO resolve domain_id vs domain_name
        domain_obj = Tenant(domain_id)
        resp_str = self._vnc_lib.network_groups_list(domain_obj)
        resp_dict = json.loads(resp_str)

        return resp_dict['network-groups']
    #end _project_list_domain

    # find networks on a given project
    def _network_list_project(self, project_id):
        # TODO resolve project_id vs project_name
        project_obj = NetworkGroup(project_id)
        resp_str = self._vnc_lib.virtual_networks_list(project_obj)
        resp_dict = json.loads(resp_str)

        return resp_dict['virtual-networks']
    #end _network_list_project

    def _port_list_project(self, project_id):
        ret_list = []
        project_nets = self._network_list_project(project_id)
        for net in project_nets:
            net_obj = self._vnc_lib.virtual_network_read(id = net['uuid'])
            for port_back_ref in net_obj.get_virtual_machine_port_back_refs():
                port_fq_name = port_back_ref['to']
                port_id = self._vnc_lib.fq_name_to_id(port_fq_name)
                port_obj = self._vnc_lib.virtual_machine_port_read(id = port_id)
                ret_info = {}
                ret_info['id'] = port_obj.uuid
                ret_list.append(ret_info)

        return ret_list
    #end _port_list_project
