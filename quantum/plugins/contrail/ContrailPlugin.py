# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

import logging
import ConfigParser
from pprint import pformat

from quantum.manager import QuantumManager
from quantum.common import exceptions as exc
#from quantum.db import api as db
from quantum.db import db_base_plugin_v2

import ctdb.config_db

LOG = logging.getLogger(__name__)

def _read_cfg(cfg_parser, section, option, default):
        try:
            val = cfg_parser.get(section, option)
        except (AttributeError,
                ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            val = default

        return val
#end _read_cfg

class ContrailPlugin(db_base_plugin_v2.QuantumDbPluginV2):
    """
    .. attention::  remove db. ref and replace ctdb. with db.
    """

    supported_extension_aliases = ["ipam", "security_groups"]
    _cfgdb = None
    _operdb = None
    _args = None

    @classmethod
    def _parse_class_args(cls, cfg_parser):
        pass
    #end _parse_class_args

    @classmethod
    def _connect_to_db(cls):
        """
        Many instantiations of plugin (base + extensions) but need to have 
	only one config db conn (else error from ifmap-server)
	"""
	if cls._cfgdb is None:
            # Initialize connection to DB and add default entries
            """
            .. attention:: TODO pick vals below from config
            """
            cls._cfgdb = ctdb.config_db.DBInterface('127.0.0.1', '8082')
            # TODO Treat the 2 DBs as logically separate? (same backend for now)
            cls._operdb = cls._cfgdb
    #end _connect_to_db

    def __init__(self):
        cfg_parser = ConfigParser.ConfigParser()
        ContrailPlugin._parse_class_args(cfg_parser)

        ContrailPlugin._connect_to_db()
        self._cfgdb = ContrailPlugin._cfgdb
    #end __init__

    # Network API handlers
    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("Plugin.create_network() called")

        net_info = self._cfgdb.network_create(network['network'])

        # verify transformation is conforming to api
        net_dict = self._make_network_dict(net_info['q_api_data'])

        net_dict.update(net_info['q_extra_data'])

        print "create_network(): " + pformat(net_dict) + "\n"
        return net_dict
    #end create_network

    def get_network(self, context, id, fields=None):
        LOG.debug("Plugin.get_network() called")

        net_info = self._cfgdb.network_read(id)

        # verify transformation is conforming to api
        net_dict = self._make_network_dict(net_info['q_api_data'], fields)

        net_dict.update(net_info['q_extra_data'])

        print "get_network(): " + pformat(net_dict) + "\n"
        return self._fields(net_dict, fields)
    #end get_network 

    def update_network(self, context, net_id, network):
        """
        Updates the attributes of a particular Virtual Network.
        """
        LOG.debug("Plugin.update_network() called")
        net_info = self._cfgdb.network_update(net_id, network['network'])

        # verify transformation is conforming to api
        net_dict = self._make_network_dict(net_info['q_api_data'])

        net_dict.update(net_info['q_extra_data'])

        print "update_network(): " + pformat(net_dict) + "\n"
        return net_dict
    #end update_network

    def delete_network(self, context, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("Plugin.delete_network() called")

        self._cfgdb.network_delete(net_id)
        print "delete_network(): " + pformat(net_id) + "\n"
    #end delete_network

    def get_networks(self, context, filters=None, fields=None):
        LOG.debug("Plugin.get_networks() called")

        nets_info = self._cfgdb.network_list(filters)

        nets_dicts = []
        for n_info in nets_info:
            # verify transformation is conforming to api
            n_dict = self._make_network_dict(n_info['q_api_data'], fields)

            n_dict.update(n_info['q_extra_data'])
            nets_dicts.append(n_dict)

        print "get_networks(): " + pformat(nets_dicts) + "\n"
        return nets_dicts
    #end get_networks

    # Subnet API handlers
    def create_subnet(self, context, subnet):
        LOG.debug("Plugin.create_subnet() called")

        subnet_info = self._cfgdb.subnet_create(subnet['subnet'])
        
        # verify transformation is conforming to api
        subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

        subnet_dict.update(subnet_info['q_extra_data'])

        print "create_subnet(): " + pformat(subnet_dict) + "\n"
        return subnet_dict
    #end create_subnet

    def get_subnet(self, context, subnet_id, fields = None):
        LOG.debug("Plugin.get_subnet() called")

        subnet_info = self._cfgdb.subnet_read(subnet_id)
        
        # verify transformation is conforming to api
        subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'], fields)

        subnet_dict.update(subnet_info['q_extra_data'])

        print "get_subnet(): " + pformat(subnet_dict) + "\n"
        return self._fields(subnet_dict, fields)
    #end get_subnet

    def update_subnet(self, context, subnet_id, subnet):
        LOG.debug("Plugin.update_subnet() called")

        subnet_info = self._cfgdb.subnet_update(subnet_id, subnet['subnet'])

        # verify transformation is conforming to api
        subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

        subnet_dict.update(subnet_info['q_extra_data'])

        print "update_subnet(): " + pformat(subnet_dict) + "\n"
        return subnet_dict
    #end update_subnet

    def delete_subnet(self, context, subnet_id):
        LOG.debug("Plugin.delete_subnet() called")

        self._cfgdb.subnet_delete(subnet_id)

        print "update_subnet(): " + pformat(subnet_id) + "\n"
    #end delete_subnet

    def get_subnets(self, context, filters = None, fields = None):
        """
        Called from Quantum API -> get_<resource>
        """
        LOG.debug("Plugin.get_subnets() called")

        subnets_info = self._cfgdb.subnets_list(filters)

        subnets_dicts = []
        for sn_info in subnets_info:
            # verify transformation is conforming to api
            sn_dict = self._make_subnet_dict(sn_info['q_api_data'], fields)

            sn_dict.update(sn_info['q_extra_data'])
            subnets_dicts.append(sn_dict)

        print "get_subnets(): " + pformat(subnets_dicts) + "\n"
        return subnets_dicts
    #end get_subnets

    # Ipam API handlers
    def create_ipam(self, context, ipam):
        """
        Creates a new IPAM, and assigns it
        a symbolic name.
        """
        LOG.debug("Plugin.create_ipam() called")

        ipam_info = self._cfgdb.ipam_create(ipam['ipam'])

        # TODO add this in extension
        ##verify transformation is conforming to api
        #ipam_dict = self._make_ipam_dict(ipam_info)
        ipam_dict = ipam_info['q_api_data']
        ipam_dict.update(ipam_info['q_extra_data'])

        print "create_ipam(): " + pformat(ipam_dict) + "\n"
        return ipam_dict
    #end create_ipam

    def get_ipam(self, context, id, fields=None):
        LOG.debug("Plugin.get_ipam() called")

        ipam_info = self._cfgdb.ipam_read(id)

        # TODO add this in extension
        ## verify transformation is conforming to api
        #ipam_dict = self._make_ipam_dict(ipam_info)
        ipam_dict = ipam_info['q_api_data']
        ipam_dict.update(ipam_info['q_extra_data'])

        print "get_ipam(): " + pformat(ipam_dict) + "\n"
        return ipam_dict
    #end get_ipam 

    def update_ipam(self, context, id, ipam_dict):
        """
        Updates the attributes of a particular IPAM.
        """
        LOG.debug("Plugin.update_ipam() called")
        ipam_info = self._cfgdb.ipam_update(id, ipam_dict)

        # TODO add this in extension
        ## verify transformation is conforming to api
        #ipam_dict = self._make_ipam_dict(ipam_info)
        ipam_dict = ipam_info['q_api_data']
        ipam_dict.update(ipam_info['q_extra_data'])

        print "update_ipam(): " + pformat(ipam_dict) + "\n"
        return ipam_dict
    #end update_ipam

    def delete_ipam(self, context, ipam_id):
        """
        Deletes the ipam with the specified identifier
        """
        LOG.debug("Plugin.delete_ipam() called")

        self._cfgdb.ipam_delete(ipam_id)

        print "delete_ipam(): " + pformat(ipam_id) + "\n"
    #end delete_ipam

    def get_ipams(self, context, filters=None, fields=None):
        LOG.debug("Plugin.get_ipams() called")

        ipams_info = self._cfgdb.ipam_list(filters)

        ipams_dicts = []
        for ipam_info in ipams_info:
            # TODO add this in extension
            # verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])
            ipams_dicts.append(ipam_dict)

        print "get_ipams(): " + pformat(ipams_dicts) + "\n"
        return ipams_dicts
    #end get_ipams

    # Port API handlers
    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("Plugin.create_port() called")
        
        port_info = self._operdb.port_create(port['port'])

        # verify transformation is conforming to api
        port_dict = self._make_port_dict(port_info['q_api_data'])

        port_dict.update(port_info['q_extra_data'])

        print "create_port(): " + pformat(port_dict) + "\n"
        return port_dict
    #end create_port

    def get_port(self, context, port_id, fields = None):
        LOG.debug("Plugin.get_port() called")
        
        port_info = self._operdb.port_read(port_id)

        # verify transformation is conforming to api
        port_dict = self._make_port_dict(port_info['q_api_data'], fields)

        port_dict.update(port_info['q_extra_data'])

        print "get_port(): " + pformat(port_dict) + "\n"
        return self._fields(port_dict, fields)
    #end get_port

    def update_port(self, context, port_id, port):
        """
        Updates the attributes of a port on the specified Virtual Network.
        """
        LOG.debug("Plugin.update_port() called")

        port_info = self._operdb.port_update(port_id, port['port'])

        # verify transformation is conforming to api
        port_dict = self._make_port_dict(port_info['q_api_data'])

        port_dict.update(port_info['q_extra_data'])

        print "update_port(): " + pformat(port_dict) + "\n"
        return port_dict
    #end update_port

    def delete_port(self, context, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        LOG.debug("Plugin.delete_port() called")

        self._operdb.port_delete(port_id)
        print "delete_port(): " + pformat(port_id) + "\n"
    #end delete_port

    def get_ports(self, context, filters=None, fields = None):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("Plugin.get_ports() called")

        # TODO validate network ownership of net_id by tenant_id
        ports_info = self._operdb.port_list(filters)

        ports_dicts = []
        for p_info in ports_info:
            # verify transformation is conforming to api
            p_dict = self._make_port_dict(p_info['q_api_data'], fields)

            p_dict.update(p_info['q_extra_data'])
            ports_dicts.append(p_dict)

        print "get_ports(): " + pformat(ports_dicts) + "\n"
        return ports_dicts
    #end get_ports

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        LOG.debug("Plugin.plug_interface() called")
        port = self._get_port(tenant_id, net_id, port_id)
        # Validate attachment
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])
        db.port_set_attachment(port_id, net_id, remote_interface_id)

    def unplug_interface(self, tenant_id, net_id, port_id):
        """
        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        LOG.debug("Plugin.unplug_interface() called")
        self._get_port(tenant_id, net_id, port_id)
        db.port_unset_attachment(port_id, net_id)

    def create_security_group(self, request):
        """
        Creates a new Security Group.
        """
        LOG.debug("Plugin.create_security_group() called")
        rsp = self._cfgdb.security_group_create(request)
        return rsp

    def create_policy(self, request, tenant_id, sg_id, pol_name, pol_descr, **kwargs):
        """
        Creates a new Policy.
        """
        LOG.debug("Plugin.create_policy() called")
        rsp = self._cfgdb.policy_create(request)
        return rsp

    def create_policy_entry_list(self, request, tenant_id, pol_id, pe_list):
        """
        Creates a new Policy Entry List.
        """
        LOG.debug("Plugin.create_policy_entry_list() called")
        self._cfgdb.policy_entry_list_create(request, tenant_id, pol_id,
	                                                  pe_list)

    def get_policy_entry(self, pe_id):
        LOG.debug("Plugin.get_policy_entry() called")
        policy_entry = self._cfgdb.policy_entry_get(pe_id)
	return policy_entry
