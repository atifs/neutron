from abc import abstractmethod

from quantum.api.v2 import attributes as attr
from quantum.api.v2 import base
from quantum.api import extensions
from quantum import manager
from oslo.config import cfg
from quantum import quota

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'floatingips': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'floating_ip_address': {'allow_post': False, 'allow_put': False,
                                'is_visible': True},
        'floating_network_id': {'allow_post': True, 'allow_put': False,
                                'validate': {'type:regex': attr.UUID_PATTERN},
                                'is_visible': True},
        'router_id': {'allow_post': False, 'allow_put': False,
                      'is_visible': True, 'default': None},
        'port_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_or_none': None},
                    'is_visible': True, 'default': None},
        'fixed_ip_address': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:ip_address_or_none': None},
                             'is_visible': True, 'default': None},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True}
    },
}

EXTERNAL = 'floatingip:external'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {EXTERNAL: {'allow_post': True,
                            'allow_put': True,
                            'default': attr.ATTR_NOT_SPECIFIED,
                            'is_visible': True,
                            'convert_to': attr.convert_to_boolean,
                            'validate': {'type:boolean': None},
                            'enforce_policy': True,
                            'required_by_policy': True}}}

l3_quota_opts = [
    cfg.IntOpt('quota_router',
               default=10,
               help='number of routers allowed per tenant, -1 for unlimited'),
    cfg.IntOpt('quota_floatingip',
               default=50,
               help='number of floating IPs allowed per tenant, '
                    '-1 for unlimited'),
]
cfg.CONF.register_opts(l3_quota_opts, 'QUOTAS')

class Floatingip(object):

    @classmethod
    def get_name(cls):
        return "Quantum Floating IP"

    @classmethod
    def get_alias(cls):
        return "floatingip"

    @classmethod
    def get_description(cls):
        return ("Floating IP extension")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/quantum/TODO"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        plugin = manager.QuantumManager.get_plugin()
        for resource_name in ['floatingip']:
            collection_name = resource_name + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())

            member_actions = {}

            quota.QUOTAS.register_resource_by_name(resource_name)

            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params,
                                              member_actions=member_actions)

            ex = extensions.ResourceExtension(collection_name,
                                              controller,
                                              member_actions=member_actions)
            exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

class FloatingIpPluginBase(object):

    @abstractmethod
    def create_floatingip(self, context, floatingip):
        pass

    @abstractmethod
    def update_floatingip(self, context, id, floatingip):
        pass

    @abstractmethod
    def get_floatingip(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_floatingip(self, context, id):
        pass

    @abstractmethod
    def get_floatingips(self, context, filters=None, fields=None):
        pass

    def _make_floatingip_dict(self, floatingip, fields=None):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address']}
        return res
