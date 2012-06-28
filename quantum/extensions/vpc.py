# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

"""The Virtual Private Cloud extension."""

import urllib
from xml.dom import minidom

from webob import exc
import webob

import logging

from quantum.api import api_common as common
from quantum.extensions import _vpc_view as vpc_view
from quantum.extensions import extensions
from quantum.manager import QuantumManager
from quantum import wsgi

LOG = logging.getLogger(__name__)

class Vpc(object):
    """VPC support"""

    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "VPC"

    @classmethod
    def get_alias(cls):
        return "vpc"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "handle vpc"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/compute/ext/vpc/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2011-07-21T00:00:00+00:00"

    @classmethod
    def get_resources(cls):
        resources = []

        # VPC definition
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/ct/tenants")
        controller = VpcController(QuantumManager.get_plugin())
        #import pdb
	#pdb.set_trace()
        res = extensions.ResourceExtension('vpc',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        return resources

class VpcController(common.QuantumController, wsgi.Controller):
    _vpc_ops_param_list = [
        {'param-name': 'vpc_name', 'required': True},
        ]

    def __init__(self, plugin):
        self._resource_name = 'vpc'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id):
        """ Creates a new vpc for a given tenant """
        try:
            body = self._deserialize(request.body, request.get_content_type())
            req_body = self._prepare_request_body(
                body, self._vpc_ops_param_list)
            req_params = req_body[self._resource_name]

        except exc.HTTPError as exp:
            return faults.Fault(exp)

        vpc = self._plugin.create_vpc(tenant_id, req_params['vpc_name'])

        builder = vpc_view.get_view_builder(request, self.version)
        result = builder.build(vpc)

        return dict(vpc = result)
