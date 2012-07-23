# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""
import requests
import re

class ConfigDBForwarder(object):
    """
    An instance of this class forwards requests to vnc cfg api (web)server
    """
    Q_URL_PREFIX = '/extensions/ct'
    def __init__(self, api_srvr_ip, api_srvr_port):
        self._api_srvr_ip = api_srvr_ip
	self._api_srvr_port = api_srvr_port

    def _request_api_server(self, request):
	# chop quantum parts of url and add api server address
	url_path = re.sub(self.Q_URL_PREFIX, '', request.environ['PATH_INFO'])
	url = "http://%s:%s%s" %(self._api_srvr_ip, self._api_srvr_port,
	                         url_path)

        if request.environ['REQUEST_METHOD'] == 'GET':
	    rsp = requests.get(url)
        elif request.environ['REQUEST_METHOD'] == 'POST':
            headers = {'Content-type': request.environ['CONTENT_TYPE']}
            rsp = requests.post(url, data = request.body, headers = headers)
        elif request.environ['REQUEST_METHOD'] == 'DELETE':
	    rsp = requests.delete(url)

	return rsp.status_code, rsp.text

    def vpc_create(self, request):
	rsp_code, rsp_data = self._request_api_server(request)
	return rsp_code, rsp_data

    def vpc_get(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def vpc_delete(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def vn_create(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def vn_get(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def vn_delete(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def subnets_set(self, request):
        rsp = self._request_api_server(request)
	return rsp

    def subnets_get(self, request):
        rsp = self._request_api_server(request)
	return rsp

    def security_group_create(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def policy_create(self, request):
	rsp = self._request_api_server(request)
	return rsp

    def policy_entry_list_create(self, request, tenant_uuid, pol_id, pe_list):
        pass
