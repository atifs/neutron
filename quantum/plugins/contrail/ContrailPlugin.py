# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

import logging
import code

from quantum.manager import QuantumManager
from quantum.common import exceptions as exc
from quantum.db import api as db

import ctdb.config_db

LOG = logging.getLogger(__name__)

class ContrailPlugin(object):
    """
    .. attention::  remove db. ref and replace ctdb. with db.
    """

    supported_extension_aliases = ["vpc", "vn", "security_groups"]
    _cfgdb = None
    _operdb = None

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
            # TOD Treat the 2 DBs as logically separate? (same backend for now)
            cls._operdb = cls._cfgdb

    def __init__(self):
        #db.configure_db({'sql_connection': 'sqlite:///:memory:'})
	ContrailPlugin._connect_to_db()
        self._cfgdb = ContrailPlugin._cfgdb

    def _get_port(self, tenant_id, network_id, port_id):

        db.validate_port_ownership(tenant_id, network_id, port_id)
        net = self._get_network(tenant_id, network_id)
        try:
            port = db.port_get(port_id, network_id)
        except:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        # Port must exist and belong to the appropriate network.
        if port['network_id'] != net['uuid']:
            raise exc.PortNotFound(net_id=network_id, port_id=port_id)
        return port

    def _validate_port_state(self, port_state):
        if port_state.upper() not in ('ACTIVE', 'DOWN'):
            raise exc.StateInvalid(port_state=port_state)
        return True

    def _validate_attachment(self, tenant_id, network_id, port_id,
                             remote_interface_id):
        for port in db.port_list(network_id):
            if port['interface_id'] == remote_interface_id:
                raise exc.AlreadyAttached(net_id=network_id,
                                          port_id=port_id,
                                          att_id=port['interface_id'],
                                          att_port_id=port['uuid'])

    def create_vpc(self, request):
        """
        Creates a new Virtual Private Cloud, and assigns it
        a symbolic name.
        """
        LOG.debug("Plugin.create_vpc() called")
        return self._cfgdb.vpc_create(request)

    def get_vpc(self, request):
        LOG.debug("Plugin.get_vpc() called")
        vpc = self._cfgdb.vpc_get(request)
	return vpc

    def delete_vpc(self, request):
        LOG.debug("Plugin.delete_vpc() called")
        result = self._cfgdb.vpc_delete(request)
	return result

    # V1.1 api
    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("Plugin.get_all_networks() called")
        filter_opts = kwargs.get('filter_opts', None)
        if not filter_opts is None and len(filter_opts) > 0:
            LOG.debug("filtering options were passed to the plugin"
                      "but the plugin does not support them")
        nets = []
        for net in db.network_list(tenant_id):
            net_item = {'net-id': str(net.uuid),
                        'net-name': net.name,
                        'net-op-status': net.op_status}
            nets.append(net_item)
        return nets

    def get_network(self, context, id, fields=None):
        LOG.debug("Plugin.get_network() called")

        net_info = self._cfgdb.network_read(id)

        return net_info
    #end get_network 

    def get_networks(self, context, filters=None, fields=None):
        LOG.debug("Plugin.get_networks() called")

        nets_info = self._cfgdb.network_list(filters)

        return nets_info 
    #end get_networks

    def get_network_details(self, tenant_id, net_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the network
        """
        LOG.debug("Plugin.get_network_details() called")
        net = self._get_network(tenant_id, net_id)
        # Retrieves ports for network
        ports = self.get_all_ports(tenant_id, net_id)
        return {'net-id': str(net.uuid),
                'net-name': net.name,
                'net-op-status': net.op_status,
                'net-ports': ports}

    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        LOG.debug("Plugin.create_network() called")

        net_name = network['network']['name']
        # tenant is project (not domain) right now
        project_id = network['network']['tenant_id']
        net_id = self._cfgdb.network_create(project_id, net_name)

        return {'id': net_id}

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("Plugin.delete_network() called")
        net = self._get_network(tenant_id, net_id)
        # Verify that no attachments are plugged into the network
        if net:
            for port in db.port_list(net_id):
                if port['interface_id']:
                    raise exc.NetworkInUse(net_id=net_id)
            db.network_destroy(net_id)
            return net
        # Network not found
        raise exc.NetworkNotFound(net_id=net_id)

    def update_network(self, tenant_id, net_id, **kwargs):
        """
        Updates the attributes of a particular Virtual Network.
        """
        LOG.debug("Plugin.update_network() called")
        net = db.network_update(net_id, tenant_id, **kwargs)
        return net

    def get_ports(self, context, filters=None, show=None, verbose=None):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("Plugin.get_all_ports() called")

        # TODO validate network ownershiop of net_id by tenant_id
        ports = self._operdb.port_list(tenant_id_filt = ['infra'],
                                       vpc_id_filt = None,
                                       vn_id_filt = None,
                                       instance_id_filt = filters['device_id'],
                                       detailed = True)
        return ports


    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("Plugin.get_port_details() called")
        port = self._get_port(tenant_id, net_id, port_id)
        return {'port-id': str(port.uuid),
                'attachment': port.interface_id,
                'port-state': port.state,
                'port-op-status': port.op_status}

    def create_port(self, context, **kwargs):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("Plugin.create_port() called")
        port = kwargs['port']['port']
        
        # TODO verify net_id
        new_port = self._operdb.port_create(port)
        port_item = {'id': new_port['id']}

        return port_item

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the attributes of a port on the specified Virtual Network.
        """
        LOG.debug("Plugin.update_port() called")
        #validate port and network ids
        self._get_network(tenant_id, net_id)
        self._get_port(tenant_id, net_id, port_id)
        port = db.port_update(port_id, net_id, **kwargs)
        port_item = {'port-id': port_id,
                     'port-state': port['state']}
        return port_item

    def delete_port(self, tenant_id, net_id, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        LOG.debug("Plugin.delete_port() called")
        net = self._get_network(tenant_id, net_id)
        port = self._get_port(tenant_id, net_id, port_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])
        try:
            port = db.port_destroy(port_id, net_id)
        except Exception, e:
            raise Exception("Failed to delete port: %s" % str(e))
        d = {}
        d["port-id"] = str(port.uuid)
        return d

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

    def create_vn(self, request):
        """
        Creates a new Virtual Network.
        """
        LOG.debug("Plugin.create_vn() called")
        rsp = self._cfgdb.vn_create(request)
        return rsp

    def get_vn(self, request):
        LOG.debug("Plugin.get_vn() called")
        vn = self._cfgdb.vn_get(request)
	return vn

    def delete_vn(self, request):
        LOG.debug("Plugin.delete_vn() called")
        result = self._cfgdb.vn_delete(request)
	return result

    def set_subnets_vnc(self, request):
        LOG.debug("Plugin.set_subnet() called")
        rsp = self._cfgdb.subnets_set(request)
	return rsp

    def get_subnets_vnc(self, request):
        LOG.debug("Plugin.get_subnets_vnc() called")
        subnets = self._cfgdb.subnets_get_vnc(request)
	return subnets

    def create_subnet(self, context, subnet):
        subnet_id = self._cfgdb.subnet_create(subnet)
        
        return {'id': subnet_id}
    #end create_subnet

    def get_subnets(self, context, filters = None, fields = None):
        """
        Called from Quantum API -> get_<resource>
        """
        LOG.debug("Plugin.get_subnets() called")

        # tenant is project (not domain) right now
        subnets = []
        subnets = self._cfgdb.subnets_read(filters)

	return subnets
    #end get_subnets

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

