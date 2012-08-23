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
from netaddr import IPAddress

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

    def subnets_set(self, request):
        rsp = self._relay_request(request)
	return rsp

    def subnets_get_vnc(self, request):
        rsp = self._relay_request(request)
	return rsp

    def subnets_get_quantum(self, subnet_ids):
        ret_subnets = []
        for subnet_id in subnet_ids:
            (vn_id, ip_addr) = self._db_cache['subnets'][subnet_id]
            # TODO query api-server to find ipam info for vn,ip pair
            subnet = {}
            subnet['cidr'] = ip_addr
            subnet['gateway_ip'] = str((IPAddress(ip_addr) &
                                        IPAddress('255.255.255.0')) |
                                       IPAddress('0.0.0.254'))
            ret_subnets.append(subnet)

        return ret_subnets
        
        
    def security_group_create(self, request):
	rsp = self._relay_request(request)
	return rsp

    def policy_create(self, request):
	rsp = self._relay_request(request)
	return rsp

    def policy_entry_list_create(self, request, tenant_uuid, pol_id, pe_list):
        pass

    # TODO put these methods in oper db class?
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
        new_port = port
        tenant_id = port['tenant_id']
        vn_id = port['network_id']
        instance_id = port['device_id']

        # TODO check for duplicate add and return

        # Create instance in oper-db if not already done
        if not self._db_cache['instances'].has_key(instance_id):
            rsp = self._instance_create(tenant_id, vn_id, instance_id)
            if rsp.status_code == 200:
                self._db_cache['instances'][instance_id] = {'port_ids': set([])}
                self._db_cache['vns'][vn_id]['instance_ids'].add(instance_id)
            else:
                raise Exception("OperDB create instance failed: %s:%s" \
                                %(rsp.status_code, rsp.text))
      
        # Create port in oper-db
        #import pdb; pdb.set_trace()
        rsp = self._port_create(tenant_id, vn_id, instance_id)
        if rsp.status_code == 200:
            rsp_port = json.loads(rsp.text)['port']
            # 'rsp_port' has vnc canonical port info. convert into
            # 'new_port' which is quantum canonical form and store in cache.
            # port_list() will pick from cache and send back this info
            port_id = rsp_port['port-id']
            port_macs = rsp_port['port-macs']
            port_ips = rsp_port['port-ips']

            new_port['id'] = rsp_port['port-id']
            new_port['mac_address'] = rsp_port['port-macs'][0]
            # TODO is this enough for subnet_id?
            import pdb; pdb.set_trace()
            fixed_ips =  \
                [{'ip_address': '%s' %(ipa),
                 'subnet_id': '%s %s' %(port_id, ipa)} for ipa in port_ips]
            new_port['fixed_ips'] = fixed_ips

            for fip in fixed_ips:
                # remember vn a subnet was assigned from
                self._db_cache['subnets'][fip['subnet_id']] = \
                                         (vn_id, fip['ip_address'])
            self._db_cache['ports'][port_id] = new_port
            self._db_cache['instances'][instance_id]['port_ids'].add(port_id)
        else:
            raise Exception("OperDB create port failed: %s:%s" \
                            %(rsp.status_code, rsp.text))

        return new_port

    def port_list(self, tenant_id_filt, vpc_id_filt, vn_id_filt,
                  instance_id_filt, detailed = False):
        # TODO query api-server and return
        # TODO optimize below if needed
        ret_ports = []
        if tenant_id_filt == None:
            tenant_set = set(self._db_cache['tenants'].keys())
        else:
            tenant_set = set(tenant_id_filt)

        for tenant_id in tenant_set:
            tenant = self._db_cache['tenants'][tenant_id]
            if vpc_id_filt == None:
                vpc_set = tenant['vpc_ids']
            else:
                vpc_set = set(vpc_id_filt) & tenant['vpc_ids']

            for vpc_id in vpc_set:
                vpc = self._db_cache['vpcs'][vpc_id]
                if vn_id_filt == None:
                    vn_set = vpc['vn_ids']
                else:
                    vn_set = set(vn_id_filt) & vpc['vn_ids']

                for vn_id in vn_set:
                    vn = self._db_cache['vns'][vn_id]
                    if instance_id_filt == None:
                       instance_set = vn['instance_ids']
                    else:
                       instance_set = set(instance_id_filt) & vn['instance_ids']

                    for instance_id in instance_set:
                        instance = self._db_cache['instances'][instance_id]
                        port_set = instance['port_ids']
                        for port_id in port_set:
                            port = self._db_cache['ports'][port_id]
                            import pdb; pdb.set_trace()
                            if detailed:
                                ret_ports.append(port)
                            else:
                                ret_ports.append(port['id'])

        return ret_ports
