# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

"""The security groups extension."""

import urllib
from xml.dom import minidom

from webob import exc
import webob

import logging

from quantum.api import api_common as common
from quantum.api import extensions
from quantum.manager import QuantumManager
from quantum import wsgi


LOG = logging.getLogger(__name__)

class SecurityGroupController(common.QuantumController, wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = 'sg'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id):
        """ Creates a new security group for a given tenant """
        security_group = self._plugin.create_security_group(request)
	return security_group

class PolicyController(common.QuantumController, wsgi.Controller):
    def __init__(self, plugin):
        self._resource_name = 'policy'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request):
        """ Creates a new policy for a given tenant """
	policy = self._plugin.create_policy(request)
	return policy

class PolicyEntryListController(common.QuantumController, wsgi.Controller):
    _policyentrylist_ops_param_list = [
        #{'param-name': 'policy_entry', 'required': True},
        #{'param-name': 'dest_vn', 'required': True},
        #{'param-name': 'ip_protocol', 'required': True},
        #{'param-name': 'port', 'required': True},
        #{'param-name': 'action', 'required': True},
	#{'param-name': 'list', 'required': True}
        ]

    def __init__(self, plugin):
        self._resource_name = 'policy_entry_list'
        self._plugin = plugin
        self.version = "1.0"

    def create(self, request, tenant_id, network_id, security_group_id,
               policy_id):
        """ Creates a new policy entry list for a given tenant """
        try:
	    import pdb
	    pdb.set_trace()
            body = self._deserialize(request.body, request.get_content_type())
            req_body = self._prepare_request_body(
                                 body, self._policyentrylist_ops_param_list)
            req_params = req_body[self._resource_name]

        except exc.HTTPError as exp:
            return faults.Fault(exp)

        self._plugin.create_policy_entry_list(tenant_id, policy_id, req_params)
        #builder = policy_entry_list_view.get_view_builder(request, self.version)
        #result = builder.build(policy_entry_list)
        #return dict(policy_entry_list=result)

    #def show(self, request, tenant_id, security_group_id, policy_id,
    #         policy_entry_id):
    #    """ Returns policy entry details for the given id """
    #    """
    #    ..attention:: try catch for not found
    #    """
    #
    #   policy_entry = self._plugin.get_policy_entry(tenant_id,
    #                                             policy_entry_id)
    #   builder = policy_entry_view.get_view_builder(request, self.version)
    #    #build response with details
    #    result = builder.build(policy_entry, True)
    #
    #    return dict(policy_entry=result)

class Security_groups(object):
    """Security group support"""

    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "SecurityGroups"

    @classmethod
    def get_alias(cls):
        return "security_groups"

    @classmethod
    def get_description(cls):
        """ Returns Ext Resource Description """
        return "handle security groups"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/compute/ext/securitygroups/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2011-07-21T00:00:00+00:00"

    @classmethod
    def get_resources(cls):
        resources = []

        # Security Group definition
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/ct/tenants")
        controller = SecurityGroupController(QuantumManager.get_plugin())
        res = extensions.ResourceExtension('sg',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        # Policy List definition
        parent_resource = dict(member_name="security_group",
                               collection_name="extensions/ct/tenants/"
                               ":(tenant_id)/networks/"
                               ":(network_id)/security_groups")
        controller = PolicyController(QuantumManager.get_plugin())
        res = extensions.ResourceExtension('policies',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        # Policy Entry definition
        parent_resource = dict(member_name="policy",
                               collection_name="extensions/ct/tenants/"
                               ":(tenant_id)/networks/"
			       ":(network_id)/security_groups/"
			       ":(security_group_id)/policies")
        controller = PolicyEntryListController(QuantumManager.get_plugin())
        res = extensions.ResourceExtension('policy_entries',
                                           controller,
					   parent = parent_resource)
        resources.append(res)

        return resources
