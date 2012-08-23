# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

"""The Virtual Network extension."""

import urllib
from xml.dom import minidom

from webob import exc, Response
import webob

import logging

from quantum.api import api_common as common
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum import wsgi

LOG = logging.getLogger(__name__)

class Virtual_network(object):
    """VN support"""

    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "VN"

    @classmethod
    def get_alias(cls):
        return "vn"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "handle vn"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/compute/ext/vn/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2011-07-21T00:00:00+00:00"

    @classmethod
    def get_resources(cls):
        resources = []

        # VN definition
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/ct/tenants")
        controller = VnController(QuantumManager.get_plugin())
        res = extensions.ResourceExtension('vn',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        # Subnet definition
        parent_resource = dict(member_name="vn",
                               collection_name="extensions/ct/tenants/"
                               ":(tenant_id)/vn")
        controller = SubnetController(QuantumManager.get_plugin())
        res = extensions.ResourceExtension('subnets',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        return resources

class VnController(common.QuantumController, wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = 'vn'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id):
        """ Creates a new VN in a given VPC """
        crt_rsp = self._plugin.create_vn(request)
	response = Response(body = crt_rsp.text,
                            headers = crt_rsp.headers)
	return response

    def show(self, request, tenant_id, id):
        """ Return details of VPC matching vpc_id """
        show_rsp = self._plugin.get_vn(request)
	response = Response(body = show_rsp.text,
                            headers = show_rsp.headers)
	return response

    def delete(self, request, tenant_id, id):
        """ Deletes VPC matching vpc_id """
        del_rsp = self._plugin.delete_vn(request)
	response = Response(body = del_rsp.text,
                            headers = del_rsp.headers)
	return response

class SubnetController(common.QuantumController, wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = 'subnets'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id, vn_id):
        """ Sets subnet list of given VN """
        crt_rsp = self._plugin.set_subnets_vnc(request)
	response = Response(body = crt_rsp.text,
                            headers = crt_rsp.headers)
	return response

    def index(self, request, tenant_id, vn_id):
        """ Gets subnet list of given VN """
        list_rsp = self._plugin.get_subnets_vnc(request)
	response = Response(body = list_rsp.text,
                            headers = list_rsp.headers)
	return response
