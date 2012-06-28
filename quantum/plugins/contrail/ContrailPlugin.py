# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

import logging
import code

from quantum.api.api_common import OperationalStatus
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

    @classmethod
    def _connect_to_config_db(cls):
        """
        Many instantiations of plugin (base + extensions) but need to have 
	only one config db conn (else error from ifmap-server)
	"""
	if cls._cfgdb is None:
            # Initialize connection to DB and add default entries
            """
            .. attention:: pick vals below from config
            """
            cls._cfgdb = ctdb.config_db.ContrailConfigDB('192.168.1.17', '8443')

    def __init__(self):
        db.configure_db({'sql_connection': 'sqlite:///:memory:'})
        ContrailPlugin._net_counter = 0
	ContrailPlugin._connect_to_config_db()


    def _get_network(self, tenant_id, network_id):

        db.validate_network_ownership(tenant_id, network_id)
        try:
            network = db.network_get(network_id)
        except:
            raise exc.NetworkNotFound(net_id=network_id)
        return network

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

    def create_vpc(self, tenant_id, vpc_name):
        """
        Creates a new Virtual Private Cloud, and assigns it
        a symbolic name.
        """
        LOG.debug("ContrailPlugin.create_vpc() called")

        vpc_id = self._cfgdb.vpc_create(tenant_id, vpc_name)

        return {'vpc-id': vpc_id}

    # V1.1 api
    def get_all_networks(self, tenant_id, **kwargs):
        """
        Returns a dictionary containing all
        <network_uuid, network_name> for
        the specified tenant.
        """
        LOG.debug("ContrailPlugin.get_all_networks() called")
        filter_opts = kwargs.get('filter_opts', None)
        if not filter_opts is None and len(filter_opts) > 0:
            LOG.debug("filtering options were passed to the plugin"
                      "but the contrail plugin does not support them")
        nets = []
        for net in db.network_list(tenant_id):
            net_item = {'net-id': str(net.uuid),
                        'net-name': net.name,
                        'net-op-status': net.op_status}
            nets.append(net_item)
        return nets

    # V2 api
    def get_networks(self, context, filters=None, show=None, verbose=None):
        #self._log("get_networks", context, filters=filters, show=show,
        #          verbose=verbose)
        if not filters is None:
            LOG.debug("filtering options were passed to the plugin"
                      "but the contrail plugin does not support them")
        nets = []
        for net in db.network_list(context.tenant_id):
            net_item = {'net-id': str(net.uuid),
                        'net-name': net.name,
                        'net-op-status': net.op_status}
            nets.append(net_item)
        return nets
        return []

    def get_network_details(self, tenant_id, net_id):
        """
        retrieved a list of all the remote vifs that
        are attached to the network
        """
        LOG.debug("ContrailPlugin.get_network_details() called")
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
        LOG.debug("ContrailPlugin.create_network() called")

        net_name = network['network']['name']
        tenant_id = context.to_dict()['tenant_id']
        if tenant_id == None:
	   """
	   .. attention:: TODO remove after quantum client is apiv2
	   """
           tenant_id = 'tenant1'

        net_id = self._cfgdb.network_create(tenant_id, net_name)

        new_net = db.network_create(tenant_id, net_name)
        # Put operational status UP
        db.network_update(new_net.uuid, net_name,
                          op_status=OperationalStatus.UP)
        # Return uuid for newly created network as net-id.
        return {'net-id': new_net.uuid}

    def delete_network(self, tenant_id, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        LOG.debug("ContrailPlugin.delete_network() called")
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
        LOG.debug("ContrailPlugin.update_network() called")
        net = db.network_update(net_id, tenant_id, **kwargs)
        return net

    def get_all_ports(self, tenant_id, net_id, **kwargs):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        LOG.debug("ContrailPlugin.get_all_ports() called")
        db.validate_network_ownership(tenant_id, net_id)
        filter_opts = kwargs.get('filter_opts', None)
        if not filter_opts is None and len(filter_opts) > 0:
            LOG.debug("filtering options were passed to the plugin"
                      "but the contrail plugin does not support them")
        port_ids = []
        ports = db.port_list(net_id)
        for x in ports:
            d = {'port-id': str(x.uuid)}
            port_ids.append(d)
        return port_ids

    def get_port_details(self, tenant_id, net_id, port_id):
        """
        This method allows the user to retrieve a remote interface
        that is attached to this particular port.
        """
        LOG.debug("ContrailPlugin.get_port_details() called")
        port = self._get_port(tenant_id, net_id, port_id)
        return {'port-id': str(port.uuid),
                'attachment': port.interface_id,
                'port-state': port.state,
                'port-op-status': port.op_status}

    def create_port(self, tenant_id, net_id, port_state=None, **kwargs):
        """
        Creates a port on the specified Virtual Network.
        """
        LOG.debug("ContrailPlugin.create_port() called")
        # verify net_id
        self._get_network(tenant_id, net_id)
        port = db.port_create(net_id, port_state)
        # Put operational status UP
        db.port_update(port.uuid, net_id,
                       op_status=OperationalStatus.UP)
        port_item = {'port-id': str(port.uuid)}
        return port_item

    def update_port(self, tenant_id, net_id, port_id, **kwargs):
        """
        Updates the attributes of a port on the specified Virtual Network.
        """
        LOG.debug("ContrailPlugin.update_port() called")
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
        LOG.debug("ContrailPlugin.delete_port() called")
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
        LOG.debug("ContrailPlugin.plug_interface() called")
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
        LOG.debug("ContrailPlugin.unplug_interface() called")
        self._get_port(tenant_id, net_id, port_id)
        db.port_unset_attachment(port_id, net_id)

    def create_vn(self, tenant_id, vpc_id, vn_name, **kwargs):
        """
        Creates a new Virtual Network.
        """
        LOG.debug("ContrailPlugin.create_vn() called")
        vn_id = self._cfgdb.vn_create(tenant_id, vpc_id, vn_name)
	#import pdb
	#pdb.set_trace()
        return {'vn-id': vn_id}

    def update_subnets(self, tenant_id, vn_id, subnets, **kwargs):
        LOG.debug("ContrailPlugin.update_subnet() called")
        subnets = self._cfgdb.subnets_set(tenant_id, vn_id, subnets)
	return {}

    def get_subnets(self, tenant_id, vn_id):
        LOG.debug("ContrailPlugin.get_subnets() called")
        subnets = self._cfgdb.subnets_get(tenant_id, vn_id)
	return subnets

    def create_security_group(self, tenant_id, vpc_id, sg_name, **kwargs):
        """
        Creates a new Security Group.
        """
        """
        .. attention:: sg_descr is being ignored
        """
        LOG.debug("ContrailPlugin.create_security_group() called")
        sg_id = self._cfgdb.security_group_create(tenant_id, vpc_id, sg_name)
	#import pdb
	#pdb.set_trace()
        return {'sg-id': sg_id}

    def create_policy(self, tenant_id, sg_id, pol_name, pol_descr, **kwargs):
        """
        Creates a new Policy.
        """
        """
        .. attention:: pol_descr is being ignored
        """
        LOG.debug("ContrailPlugin.create_policy() called")
        pol_id = self._cfgdb.policy_create(tenant_id, sg_id, pol_name)
        return {'policy-id': pol_id}

    def create_policy_entry_list(self, tenant_id, pol_id, pe_list):
        """
        Creates a new Policy Entry List.
        """
        LOG.debug("ContrailPlugin.create_policy_entry_list() called")
        self._cfgdb.policy_entry_list_create(tenant_id, pol_id,
	                                                  pe_list)

    def get_policy_entry(self, pe_id):
        LOG.debug("ContrailPlugin.get_policy_entry() called")
        policy_entry = self._cfgdb.policy_entry_get(pe_id)

