# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

"""The Virtual Private Cloud extension."""

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
        res = extensions.ResourceExtension('vpc',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        return resources

class VpcController(common.QuantumController, wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = 'vpc'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id):
        """ Creates a new vpc for a given tenant """
        crt_rsp = self._plugin.create_vpc(request)
	response = Response(body = crt_rsp.text,
                            headers = crt_rsp.headers)
	return response

    def show(self, request, tenant_id, id):
        """ Return details of VPC matching vpc_id """
        show_rsp = self._plugin.get_vpc(request)
	response = Response(body = show_rsp.text,
                            headers = show_rsp.headers)
	return response

    def delete(self, request, tenant_id, id):
        """ Deletes VPC matching vpc_id """
        del_rsp = self._plugin.delete_vpc(request)
	response = Response(body = del_rsp.text,
                            headers = del_rsp.headers)
	return response
