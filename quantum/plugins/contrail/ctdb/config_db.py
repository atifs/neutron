# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

import uuid

from xml.etree import ElementTree

from ifmap_client.ifmap.client import client, namespaces
from ifmap_client.ifmap.request import NewSessionRequest, RenewSessionRequest, EndSessionRequest, PublishRequest, SearchRequest, SubscribeRequest, PurgeRequest, PollRequest
from ifmap_client.ifmap.id import IPAddress, MACAddress, Device, AccessRequest, Identity, CustomIdentity
from ifmap_client.ifmap.operations import PublishUpdateOperation, PublishNotifyOperation, PublishDeleteOperation, SubscribeUpdateOperation, SubscribeDeleteOperation
from ifmap_client.ifmap.util import attr, link_ids
from ifmap_client.ifmap.response import Response, newSessionResult
from ifmap_client.ifmap.metadata import Metadata

def network_alloc_ifmap_id(tenant_uuid, net_name):
    return "ct:network:%s:%s" %(tenant_uuid, net_name)

def security_group_alloc_ifmap_id(tenant_uuid, sg_name):
    return "ct:sg:%s:%s" %(tenant_uuid, sg_name)

def policy_alloc_ifmap_id(tenant_uuid, pol_name):
    # policy name not qualified by security group name
    return "ct:pol:%s:%s" %(tenant_uuid, pol_name)

def tenant_get_ifmap_id(tenant_uuid):
    return "ct:tenant:%s" %(tenant_uuid)

def security_group_get_ifmap_id(sg_id):
    return sg_id

def policy_get_ifmap_id(pol_id):
    return pol_id

class ContrailConfigDB(object):
    def __init__(self, srvr_ip, srvr_port):
        meta_perms = "<ct:mperms>" + \
                     "    <ct:owner> u1 </ct:owner>" + \
                     "    <ct:group> g1 </ct:group>" + \
                     "    <ct:uperm> rwx </ct:uperm>" + \
                     "    <ct:gperm> rwx </ct:gperm>" + \
                     "    <ct:operm> rwx </ct:operm>" + \
                     "</ct:mperms>"
        """
	.. attention:: username/passwd from right place
        """
        # Connect to IF-MAP server
        mapclient = client("https://%s:%s" %(srvr_ip, srvr_port),
                            'test', 'test', namespaces)

        self._mapclient = mapclient

        result = mapclient.call('newSession', NewSessionRequest())
        mapclient.set_session_id(newSessionResult(result).get_session_id())
        mapclient.set_publisher_id(newSessionResult(result).get_publisher_id())

        # Publish init config
        meta = str(Metadata('iperms', 'rwxrwxrwx',
                        {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                        elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = "ct:cloud",
                                                type = "other",
                                                other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

        meta = str(Metadata('iperms', 'rwxrwxrwx',
                        {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                        elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = "ct:tenant:infra",
                                                type = "other",
                                                other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

        meta = str(Metadata('member-of', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = "ct:cloud",
                                                type = "other",
                                                other_type = "extended")),
                             id2 = str(Identity(name = "ct:tenant:infra",
                                                type = "other",
                                                other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

    def network_create(self, tenant_uuid, net_name):
        net_imid = network_alloc_ifmap_id(tenant_uuid, net_name)
        tenant_imid = tenant_get_ifmap_id(tenant_uuid)
 
        meta_perms = "<ct:mperms>" + \
                     "    <ct:owner> u1 </ct:owner>" + \
                     "    <ct:group> g1 </ct:group>" + \
                     "    <ct:uperm> rwx </ct:uperm>" + \
                     "    <ct:gperm> rwx </ct:gperm>" + \
                     "    <ct:operm> rwx </ct:operm>" + \
                     "</ct:mperms>"
        mapclient = self._mapclient

        meta = str(Metadata('iperms', 'rwxrwxrwx',
                        {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                        elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(
                                           name = net_imid,
                                           type = "other",
                                           other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)
 
        meta = str(Metadata('belongs-to', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = tenant_imid,
                                                type = "other",
                                                other_type = "extended")),
                             id2 = str(Identity(name = net_imid,
                                                type = "other",
                                                other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

    def security_group_create(self, tenant_uuid, sg_name):
        sg_imid = security_group_alloc_ifmap_id(tenant_uuid, sg_name)
        tenant_imid = tenant_get_ifmap_id(tenant_uuid)
 
        meta_perms = "<ct:mperms>" + \
                     "    <ct:owner> u1 </ct:owner>" + \
                     "    <ct:group> g1 </ct:group>" + \
                     "    <ct:uperm> rwx </ct:uperm>" + \
                     "    <ct:gperm> rwx </ct:gperm>" + \
                     "    <ct:operm> rwx </ct:operm>" + \
                     "</ct:mperms>"
        mapclient = self._mapclient

        meta = str(Metadata('iperms', 'rwxrwxrwx',
                        {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                        elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(
                                           name = sg_imid,
                                           type = "other",
                                           other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)
 

        meta = str(Metadata('belongs-to', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = tenant_imid,
                                                type = "other",
                                                other_type = "extended")),
                             id2 = str(Identity(name = sg_imid,
                                                type = "other",
                                                other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

	return sg_imid

    def policy_create(self, tenant_uuid, sg_id, pol_name):
        pol_imid = policy_alloc_ifmap_id(tenant_uuid, pol_name)
        sg_imid = security_group_get_ifmap_id(sg_id)
 
        meta_perms = "<ct:mperms>" + \
                     "    <ct:owner> u1 </ct:owner>" + \
                     "    <ct:group> g1 </ct:group>" + \
                     "    <ct:uperm> rwx </ct:uperm>" + \
                     "    <ct:gperm> rwx </ct:gperm>" + \
                     "    <ct:operm> rwx </ct:operm>" + \
                     "</ct:mperms>"
        mapclient = self._mapclient

        meta = str(Metadata('iperms', 'rwxrwxrwx',
                        {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                        elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(
                                           name = sg_imid,
                                           type = "other",
                                           other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)
 
        meta = str(Metadata('belongs-to', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_perms))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = sg_imid,
                                                type = "other",
                                                other_type = "extended")),
                             id2 = str(Identity(name = pol_imid,
                                                type = "other",
                                                other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

	return pol_imid

    def policy_entry_list_create(self, tenant_uuid, pol_id, pe_list):
        """
	policy_entry_list is a list updated in full by end-user agent
	at all operations
	"""

        pol_imid = policy_get_ifmap_id(pol_id)
        meta_pe_list = "<ct:policy_entry_list>"
	for pe in pe_list:
	    meta_pe_list += \
	        "  <ct:policy_entry>" + \
	        "      <ct:dir> %s </ct:dir>" %(pe['direction']) + \
	        "      <ct:vn> %s </ct:vn>" %(pe['other_vn']) + \
	        "      <ct:proto> %s </ct:proto>" %(pe['ip_proto']) + \
	        "      <ct:port> %s </ct:port>" %(pe['port']) + \
	        "      <ct:action> %s </ct:action>" %(pe['action']) + \
	        "  </ct:policy_entry>"
        meta_pe_list += "</ct:policy_entry_list>"

        mapclient = self._mapclient
        meta = str(Metadata('policy-entries', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_pe_list))

        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(
                                           name = pol_imid,
                                           type = "other",
                                           other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)
