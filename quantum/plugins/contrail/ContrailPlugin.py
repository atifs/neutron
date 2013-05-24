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
from quantum.db import db_base_plugin_v2
from quantum.extensions import floatingip

from quantum.openstack.common import cfg
from httplib2 import Http
import re
import string

import ctdb.config_db

LOG = logging.getLogger(__name__)

vnc_opts = [
    cfg.StrOpt('api_server_ip', default = '127.0.0.1'),
    cfg.StrOpt('api_server_port', default = '8082'),
]

def _read_cfg(cfg_parser, section, option, default):
        try:
            val = cfg_parser.get(section, option)
        except (AttributeError,
                ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            val = default

        return val
#end _read_cfg

def _read_cfg_boolean(cfg_parser, section, option, default):
        try:
            val = cfg_parser.getboolean(section, option)
        except (AttributeError, ValueError,
                ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            val = default

        return val
#end _read_cfg

#TODO define ABC PluginBase for ipam and policy and derive mixin from them
class ContrailPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                     floatingip.FloatingIpPluginBase):
    """
    .. attention::  TODO remove db. ref and replace ctdb. with db.
    """

    supported_extension_aliases = ["ipam", "policy", "security_groups",
                                   "floatingip"]
    _cfgdb = None
    _args = None
    _tenant_id_dict = {}
    _tenant_name_dict = {}

    @classmethod
    def _parse_class_args(cls, cfg_parser):
        cfg_parser.read("/etc/quantum/plugins/contrail/contrail_plugin.ini")
        cls._multi_tenancy = _read_cfg_boolean(cfg_parser, 'APISERVER', 'multi_tenancy', False)
        cls._admin_token   = _read_cfg(cfg_parser, 'KEYSTONE', 'admin_token', '')
        cls._auth_url      = _read_cfg(cfg_parser, 'KEYSTONE', 'auth_url', '')
        cls._admin_user    = _read_cfg(cfg_parser, 'KEYSTONE', 'admin_user', 'user1')
        cls._admin_password = _read_cfg(cfg_parser, 'KEYSTONE', 'admin_password', 'password1')
        cls._admin_tenant_name = _read_cfg(cfg_parser, 'KEYSTONE', 'admin_tenant_name', 'default-domain')
        cls._tenants_api   = '%s/tenants' % (cls._auth_url)
        pass
    #end _parse_class_args

    @classmethod
    def _connect_to_db(cls):
        """
        Many instantiations of plugin (base + extensions) but need to have 
	only one config db conn (else error from ifmap-server)
	"""
        cls._cfgdb_map = {}
        if cls._cfgdb is None:
            # Initialize connection to DB and add default entries
            cls._cfgdb = ctdb.config_db.DBInterface(cls._admin_user, cls._admin_password, cls._admin_tenant_name,
                                                    cfg.CONF.APISERVER.api_server_ip,
                                                    cfg.CONF.APISERVER.api_server_port)
            cls._cfgdb.manager = cls
    #end _connect_to_db

    @classmethod
    def _get_user_cfgdb(cls, context):
        if not cls._multi_tenancy:
            return cls._cfgdb
        user_id = context.user_id
        role = string.join(context.roles, ",")
        if not user_id in cls._cfgdb_map:
            cls._cfgdb_map[user_id] = ctdb.config_db.DBInterface(cls._admin_user, cls._admin_password, cls._admin_tenant_name,
                                                    cfg.CONF.APISERVER.api_server_ip,
                                                    cfg.CONF.APISERVER.api_server_port, 
                                                    user_info = {'user_id' : user_id, 'role': role})
            cls._cfgdb_map[user_id].manager = cls

        return cls._cfgdb_map[user_id]
    #end _get_cfgdb

    @classmethod
    def _tenant_list_from_keystone(cls):
        # get all tenants
        hdrs = {'X-Auth-Token': cls._admin_token, 'Content-Type': 'application/json'}
        try:
            rsp, content = Http().request(cls._tenants_api, method="GET", headers=hdrs)
            if rsp.status != 200:
                return
        except:
            return

        # transform needed for python compatibility
        content = re.sub('true', 'True', content)
        content = re.sub('null', 'None', content)
        content = eval(content)

        # bail if response is unexpected 
        if 'tenants' not in content: 
            return

        # create a dictionary for id->name and name->id mapping
        for tenant in content['tenants']:
            print 'Adding tenant %s:%s to cache' % (tenant['name'], tenant['id'])
            cls._tenant_id_dict[tenant['id']]   = tenant['name']
            cls._tenant_name_dict[tenant['name']] = tenant['id']
    #end _tenant_list_from_keystone

    def __init__(self):
        cfg.CONF.register_opts(vnc_opts, 'APISERVER')

        cfg_parser = ConfigParser.ConfigParser()
        ContrailPlugin._parse_class_args(cfg_parser)

        ContrailPlugin._connect_to_db()
        self._cfgdb = ContrailPlugin._cfgdb

        ContrailPlugin._tenant_list_from_keystone()
    #end __init__

    @classmethod
    def tenant_id_to_name(cls, id):
        # bail if we never built the list successfully
        if len(cls._tenant_id_dict) == 0:
            return id
        # check cache 
        if id in cls._tenant_id_dict:
            return cls._tenant_id_dict[id]
        # otherwise refresh 
        cls._tenant_list_from_keystone()
        # second time's a charm?
        return cls._tenant_id_dict[id] if id in cls._tenant_id_dict else id
    #end tenant_id_to_name

    @classmethod
    def tenant_name_to_id(cls, name):
        # bail if we never built the list successfully
        if len(cls._tenant_name_dict) == 0:
            return name
        # check cache 
        if name in cls._tenant_name_dict:
            return cls._tenant_name_dict[name]
        # otherwise refresh 
        cls._tenant_list_from_keystone()
        # second time's a charm?
        return cls._tenant_name_dict[name] if name in cls._tenant_name_dict else name
    #end tenant_name_to_id

    # Network API handlers
    def create_network(self, context, network):
        """
        Creates a new Virtual Network, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            net_info = cfgdb.network_create(network['network'])

            # verify transformation is conforming to api
            net_dict = self._make_network_dict(net_info['q_api_data'])

            net_dict.update(net_info['q_extra_data'])

            LOG.debug("create_network(): " + pformat(net_dict) + "\n")
            return net_dict
        except Exception as e:
            LOG.error("create_network(): Exception - " + str(e) + "\n")
            raise e
    #end create_network

    def get_network(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            net_info = cfgdb.network_read(id)

            # verify transformation is conforming to api
            net_dict = self._make_network_dict(net_info['q_api_data'], fields)

            net_dict.update(net_info['q_extra_data'])

            LOG.debug("get_network(): " + pformat(net_dict))
            return self._fields(net_dict, fields)
        except Exception as e:
            LOG.error("get_network(): Exception - " + str(e) + "\n")
            raise e
    #end get_network 

    def update_network(self, context, net_id, network):
        """
        Updates the attributes of a particular Virtual Network.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            net_info = cfgdb.network_update(net_id, network['network'])

            # verify transformation is conforming to api
            net_dict = self._make_network_dict(net_info['q_api_data'])

            net_dict.update(net_info['q_extra_data'])

            LOG.debug("update_network(): " + pformat(net_dict))
            return net_dict
        except Exception as e:
            LOG.error("update_network(): Exception - " + str(e) + "\n")
            raise e
    #end update_network

    def delete_network(self, context, net_id):
        """
        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.network_delete(net_id)
            LOG.debug("delete_network(): " + pformat(net_id))
        except Exception as e:
            LOG.error("delete_network(): Exception - " + str(e) + "\n")
            raise e
    #end delete_network

    def get_networks(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            nets_info = cfgdb.network_list(filters)

            nets_dicts = []
            for n_info in nets_info:
                # verify transformation is conforming to api
                n_dict = self._make_network_dict(n_info['q_api_data'], fields)

                n_dict.update(n_info['q_extra_data'])
                nets_dicts.append(n_dict)

            LOG.debug("get_networks(): filters: " + pformat(filters) + " data: " + pformat(nets_dicts))
            return nets_dicts
        except Exception as e:
            LOG.error("get_networks(): Exception - " + str(e) + "\n")
            raise e
    #end get_networks

    # Subnet API handlers
    def create_subnet(self, context, subnet):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnet_info = cfgdb.subnet_create(subnet['subnet'])
            
            # verify transformation is conforming to api
            subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

            subnet_dict.update(subnet_info['q_extra_data'])

            LOG.debug("create_subnet(): " + pformat(subnet_dict))
            return subnet_dict
        except Exception as e:
            LOG.error("create_subnet(): Exception - " + str(e) + "\n")
            raise e
    #end create_subnet

    def get_subnet(self, context, subnet_id, fields = None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnet_info = cfgdb.subnet_read(subnet_id)
            
            # verify transformation is conforming to api
            subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'], fields)

            subnet_dict.update(subnet_info['q_extra_data'])

            LOG.debug("get_subnet(): " + pformat(subnet_dict)) 
            return self._fields(subnet_dict, fields)
        except Exception as e:
            LOG.error("create_subnet(): Exception - " + str(e) + "\n")
            raise e
    #end get_subnet

    def update_subnet(self, context, subnet_id, subnet):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnet_info = cfgdb.subnet_update(subnet_id, subnet['subnet'])

            # verify transformation is conforming to api
            subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

            subnet_dict.update(subnet_info['q_extra_data'])

            LOG.debug("update_subnet(): " + pformat(subnet_dict))
            return subnet_dict
        except Exception as e:
            LOG.error("update_subnet(): Exception - " + str(e) + "\n")
            raise e
    #end update_subnet

    def delete_subnet(self, context, subnet_id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.subnet_delete(subnet_id)

            LOG.debug("delete_subnet(): " + pformat(subnet_id))
        except Exception as e:
            LOG.error("delete_subnet(): Exception - " + str(e) + "\n")
            raise e
    #end delete_subnet

    def get_subnets(self, context, filters = None, fields = None):
        """
        Called from Quantum API -> get_<resource>
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            subnets_info = cfgdb.subnets_list(filters)

            subnets_dicts = []
            for sn_info in subnets_info:
                # verify transformation is conforming to api
                sn_dict = self._make_subnet_dict(sn_info['q_api_data'], fields)

                sn_dict.update(sn_info['q_extra_data'])
                subnets_dicts.append(sn_dict)

            LOG.debug("get_subnets(): filters: " + pformat(filters) + " data: " + pformat(subnets_dicts))
            return subnets_dicts
        except Exception as e:
            LOG.error("get_subnets(): Exception - " + str(e) + "\n")
            raise e
    #end get_subnets

    # Ipam API handlers
    def create_ipam(self, context, ipam):
        """
        Creates a new IPAM, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_create(ipam['ipam'])

            # TODO add this in extension
            ##verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("create_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            LOG.error("create_ipam(): Exception - " + str(e) + "\n")
            raise e
    #end create_ipam

    def get_ipam(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_read(id)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("get_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            LOG.error("get_ipam(): Exception - " + str(e) + "\n")
            raise e
    #end get_ipam 

    def update_ipam(self, context, id, ipam):
        """
        Updates the attributes of a particular IPAM.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipam_info = cfgdb.ipam_update(id, ipam)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            ipam_dict = ipam_info['q_api_data']
            ipam_dict.update(ipam_info['q_extra_data'])

            LOG.debug("update_ipam(): " + pformat(ipam_dict))
            return ipam_dict
        except Exception as e:
            LOG.error("update_ipam(): Exception - " + str(e) + "\n")
            raise e
    #end update_ipam

    def delete_ipam(self, context, ipam_id):
        """
        Deletes the ipam with the specified identifier
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.ipam_delete(ipam_id)

            LOG.debug("delete_ipam(): " + pformat(ipam_id))
        except Exception as e:
            LOG.error("delete_ipam(): Exception - " + str(e) + "\n")
            raise e
    #end delete_ipam

    def get_ipams(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            ipams_info = cfgdb.ipam_list(filters)

            ipams_dicts = []
            for ipam_info in ipams_info:
                # TODO add this in extension
                # verify transformation is conforming to api
                #ipam_dict = self._make_ipam_dict(ipam_info)
                ipam_dict = ipam_info['q_api_data']
                ipam_dict.update(ipam_info['q_extra_data'])
                ipams_dicts.append(ipam_dict)

            LOG.debug("get_ipams(): " + pformat(ipams_dicts))
            return ipams_dicts
        except Exception as e:
            LOG.error("get_ipams(): Exception - " + str(e) + "\n")
            raise e
    #end get_ipams

    # Policy API handlers
    def create_policy(self, context, policy):
        """
        Creates a new Policy, and assigns it
        a symbolic name.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_info = cfgdb.policy_create(policy['policy'])

            # TODO add this in extension
            ##verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("create_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            LOG.error("create_policy(): Exception - " + str(e) + "\n")
            raise e
    #end create_policy

    def get_policy(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_info = cfgdb.policy_read(id)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("get_policy(): " + pformat(policy_dict)) 
            return policy_dict
        except Exception as e:
            LOG.error("get_policy(): Exception - " + str(e) + "\n")
            raise e
    #end get_policy

    def update_policy(self, context, id, policy):
        """
        Updates the attributes of a particular Policy.
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policy_info = cfgdb.policy_update(id, policy)

            # TODO add this in extension
            ## verify transformation is conforming to api
            #ipam_dict = self._make_ipam_dict(ipam_info)
            policy_dict = policy_info['q_api_data']
            policy_dict.update(policy_info['q_extra_data'])

            LOG.debug("update_policy(): " + pformat(policy_dict))
            return policy_dict
        except Exception as e:
            LOG.error("update_policy(): Exception - " + str(e) + "\n")
            raise e
    #end update_policy

    def delete_policy(self, context, policy_id):
        """
        Deletes the Policy with the specified identifier
        """
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.policy_delete(policy_id)

            LOG.debug("delete_policy(): " + pformat(policy_id)) 
        except Exception as e:
            LOG.error("delete_policy(): Exception - " + str(e) + "\n")
            raise e
    #end delete_policy

    def get_policys(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            policys_info = cfgdb.policy_list(filters)

            policys_dicts = []
            for policy_info in policys_info:
                # TODO add this in extension
                # verify transformation is conforming to api
                #ipam_dict = self._make_ipam_dict(ipam_info)
                policy_dict = policy_info['q_api_data']
                policy_dict.update(policy_info['q_extra_data'])
                policys_dicts.append(policy_dict)

            LOG.debug("get_policys(): " + pformat(policys_dicts))
            return policys_dicts
        except Exception as e:
            LOG.error("get_policys(): Exception - " + str(e) + "\n")
            raise e
    #end get_policys

    # Floating IP API handlers
    def create_floatingip(self, context, floatingip):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fip_info = cfgdb.floatingip_create(floatingip['floatingip'])

            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fip_dict.update(fip_info['q_extra_data'])

            LOG.debug("create_floatingip(): " + pformat(fip_dict))
            return fip_dict
        except Exception as e:
            LOG.error("create_floatingip(): Exception - " + str(e) + "\n")
            raise e
    #end create_floatingip

    def update_floatingip(self, context, fip_id, floatingip):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fip_info = cfgdb.floatingip_update(fip_id, floatingip['floatingip'])

            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fip_dict.update(fip_info['q_extra_data'])

            LOG.debug("update_floatingip(): " + pformat(fip_dict)) 
            return fip_dict
        except Exception as e:
            LOG.error("update_floatingip(): Exception - " + str(e) + "\n")
            raise e
    #end update_floatingip

    def get_floatingip(self, context, id, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fip_info = cfgdb.floatingip_read(id)

            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fip_dict.update(fip_info['q_extra_data'])

            LOG.debug("get_floatingip(): " + pformat(fip_dict))
            return fip_dict
        except Exception as e:
            LOG.error("get_floatingip(): Exception - " + str(e) + "\n")
            raise e
    #end get_floatingip

    def delete_floatingip(self, context, fip_id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            cfgdb.floatingip_delete(fip_id)
            LOG.debug("delete_floating(): " + pformat(fip_id)) 
        except Exception as e:
            LOG.error("delete_floatingip(): Exception - " + str(e) + "\n")
            raise e
    #end delete_floatingip

    def get_floatingips(self, context, filters=None, fields=None):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
            fips_info = cfgdb.floatingip_list(filters)

            fips_dicts = []
            for fip_info in fips_info:
                # verify transformation is conforming to api
                fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

                fip_dict.update(fip_info['q_extra_data'])
                fips_dicts.append(fip_dict)

            LOG.debug("get_floatingips(): " + pformat(fips_dicts)) 
            return fips_dicts
        except Exception as e:
            LOG.error("get_floatingips(): Exception - " + str(e) + "\n")
            raise e
    #end get_floatingips

    # Port API handlers
    def create_port(self, context, port):
        """
        Creates a port on the specified Virtual Network.
        """
        try:
            port_info = self._cfgdb.port_create(port['port'])

            # verify transformation is conforming to api
            port_dict = self._make_port_dict(port_info['q_api_data'])

            port_dict.update(port_info['q_extra_data'])

            LOG.debug("create_port(): " + pformat(port_dict)) 
            return port_dict
        except Exception as e:
            LOG.error("create_port(): Exception - " + str(e) + "\n")
            raise e
    #end create_port

    def get_port(self, context, port_id, fields = None):
        try:
            port_info = self._cfgdb.port_read(port_id)

            # verify transformation is conforming to api
            port_dict = self._make_port_dict(port_info['q_api_data'], fields)

            port_dict.update(port_info['q_extra_data'])

            LOG.debug("get_port(): " + pformat(port_dict))
            return self._fields(port_dict, fields)
        except Exception as e:
            LOG.error("get_port(): Exception - " + str(e) + "\n")
            raise e
    #end get_port

    def update_port(self, context, port_id, port):
        """
        Updates the attributes of a port on the specified Virtual Network.
        """
        try:
            port_info = self._cfgdb.port_update(port_id, port['port'])

            # verify transformation is conforming to api
            port_dict = self._make_port_dict(port_info['q_api_data'])

            port_dict.update(port_info['q_extra_data'])

            LOG.debug("update_port(): " + pformat(port_dict)) 
            return port_dict
        except Exception as e:
            LOG.error("update_port(): Exception - " + str(e) + "\n")
            raise e
    #end update_port

    def delete_port(self, context, port_id):
        """
        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        try:
            self._cfgdb.port_delete(port_id)
            LOG.debug("delete_port(): " + pformat(port_id))
        except Exception as e:
            LOG.error("delete_port(): Exception - " + str(e) + "\n")
            raise e
    #end delete_port

    def get_ports(self, context, filters=None, fields = None):
        """
        Retrieves all port identifiers belonging to the
        specified Virtual Network.
        """
        try:
            # TODO validate network ownership of net_id by tenant_id
            ports_info = self._cfgdb.port_list(filters)

            ports_dicts = []
            for p_info in ports_info:
                # verify transformation is conforming to api
                p_dict = self._make_port_dict(p_info['q_api_data'], fields)

                p_dict.update(p_info['q_extra_data'])
                ports_dicts.append(p_dict)

            LOG.debug("get_ports(): filter: " +pformat(filters) + 'data: ' + pformat(ports_dicts))
            return ports_dicts
        except Exception as e:
            LOG.error("get_ports(): Exception - " + str(e) + "\n")
            raise e
    #end get_ports

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """
        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
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
        self._get_port(tenant_id, net_id, port_id)
        db.port_unset_attachment(port_id, net_id)

    def create_security_group(self, request):
        """
        Creates a new Security Group.
        """
        cfgdb = ContrailPlugin._get_user_cfgdb(context)
        rsp = cfgdb.security_group_create(request)
        return rsp
