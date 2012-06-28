# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

"""The Virtual Network extension."""

import urllib
from xml.dom import minidom

from webob import exc
import webob

import logging

from quantum.api import api_common as common
from quantum.extensions import _virtual_network_view as vn_view
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
        #import pdb
	#pdb.set_trace()
        res = extensions.ResourceExtension('vn',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        # Subnet definition
        parent_resource = dict(member_name="vn",
                               collection_name="extensions/ct/tenants/"
                               ":(tenant_id)/vn")
                               #":(network_id)/security_groups")
        controller = SubnetController(QuantumManager.get_plugin())
        res = extensions.ResourceExtension('subnets',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        return resources

class VnController(common.QuantumController, wsgi.Controller):
    _vn_ops_param_list = [
        {'param-name': 'vn_vpc_id', 'required': True},
        {'param-name': 'vn_name', 'required': True},
        ]

    def __init__(self, plugin):
        self._resource_name = 'vn'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id):
        """ Creates a new VN in a given VPC """
        try:
            body = self._deserialize(request.body, request.get_content_type())
            req_body = self._prepare_request_body(
                body, self._vn_ops_param_list)
            req_params = req_body[self._resource_name]

        except exc.HTTPError as exp:
            return faults.Fault(exp)

        vn = self._plugin.create_vn(tenant_id, req_params['vn_vpc_id'],
	                            req_params['vn_name'])

        builder = vn_view.get_vn_view_builder(request, self.version)
        result = builder.build(vn)

        return dict(vn = result)

class SubnetController(common.QuantumController, wsgi.Controller):
    _subnet_ops_param_list = [
	]

    def __init__(self, plugin):
        self._resource_name = 'subnets'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id, vn_id):
        """ Sets subnet list of given VN """
        try:
            body = self._deserialize(request.body, request.get_content_type())
            req_body = self._prepare_request_body(
                body, self._subnet_ops_param_list)
            req_params = req_body[self._resource_name]

        except exc.HTTPError as exp:
            return faults.Fault(exp)

        subnets = self._plugin.update_subnets(tenant_id, vn_id, req_params)

        builder = vn_view.get_subnet_view_builder()
        result = builder.build(subnets)

        return dict(subnets = result)

    def index(self, request, tenant_id, vn_id):
        """ Gets subnet list of given VN """

        subnets = self._plugin.get_subnets(tenant_id, vn_id)
        builder = vn_view.get_subnet_view_builder()
        result = builder.build(subnets)

        return dict(subnets = result)
