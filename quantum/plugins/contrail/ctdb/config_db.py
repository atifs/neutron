# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

import sys
import uuid

from xml.etree import ElementTree

import lxml
import StringIO
import re

sys.path.append("/home/ajayhn/ifmap-client")
from ifmap.client import client, namespaces
from ifmap.request import NewSessionRequest, RenewSessionRequest, EndSessionRequest, PublishRequest, SearchRequest, SubscribeRequest, PurgeRequest, PollRequest
from ifmap.id import IPAddress, MACAddress, Device, AccessRequest, Identity, CustomIdentity
from ifmap.operations import PublishUpdateOperation, PublishNotifyOperation, PublishDeleteOperation, SubscribeUpdateOperation, SubscribeDeleteOperation
from ifmap.util import attr, link_ids
from ifmap.response import Response, newSessionResult
from ifmap.metadata import Metadata

def vpc_alloc_ifmap_id(tenant_uuid, vpc_name):
    return "ct:vpc:%s:%s" %(tenant_uuid, vpc_name)

def vn_alloc_ifmap_id(tenant_uuid, vn_name):
    return "ct:vn:%s:%s" %(tenant_uuid, vn_name)

def security_group_alloc_ifmap_id(tenant_uuid, sg_name):
    return "ct:sg:%s:%s" %(tenant_uuid, sg_name)

def policy_alloc_ifmap_id(tenant_uuid, pol_name):
    # policy name not qualified by security group name
    return "ct:pol:%s:%s" %(tenant_uuid, pol_name)

def tenant_get_ifmap_id(tenant_uuid):
    return "ct:tenant:%s" %(tenant_uuid)

def vpc_get_ifmap_id(vpc_id):
    return vpc_id

def vn_get_ifmap_id(net_id):
    return net_id

def security_group_get_ifmap_id(sg_id):
    return sg_id

def policy_get_ifmap_id(pol_id):
    return pol_id

class ContrailConfigDB(object):
    META_PERMS = "<ct:mperms>" + \
                 "    <ct:owner> u1 </ct:owner>" + \
                 "    <ct:group> g1 </ct:group>" + \
                 "    <ct:uperm> rwx </ct:uperm>" + \
                 "    <ct:gperm> rwx </ct:gperm>" + \
                 "    <ct:operm> rwx </ct:operm>" + \
                 "</ct:mperms>"

    def __init__(self, srvr_ip, srvr_port):
        """
	.. attention:: username/passwd from right place
        """
        # Connect to IF-MAP server
        #mapclient = client("https://%s:%s" %(srvr_ip, srvr_port),
        #                    'test', 'test', namespaces)
        mapclient = client(("%s" %(srvr_ip), "%s" %(srvr_port)),
                            'test', 'test', namespaces)

        self._mapclient = mapclient

        result = mapclient.call('newSession', NewSessionRequest())
        mapclient.set_session_id(newSessionResult(result).get_session_id())
        mapclient.set_publisher_id(newSessionResult(result).get_publisher_id())

        # Publish init config
	self.publish_id_self_meta("ct:cloud")
	self.publish_id_self_meta("ct:tenant:infra")

        meta = str(Metadata('member-of', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = self.META_PERMS))
        self.publish_id_pair_meta("ct:cloud", "ct:tenant:infra", meta)

    def publish_id_self_meta(self, self_imid):
        mapclient = self._mapclient

        meta = str(Metadata('iperms', 'rwxrwxrwx',
                        {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                        elements = self.META_PERMS))
        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(
                                           name = self_imid,
                                           type = "other",
                                           other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

    def publish_id_pair_meta(self, id1, id2, metadata):
        mapclient = self._mapclient

        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(name = id1,
                                                type = "other",
                                                other_type = "extended")),
                             id2 = str(Identity(name = id2,
                                                type = "other",
                                                other_type = "extended")),
                             metadata = metadata,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)
 

    def vpc_create(self, tenant_uuid, vpc_name):
        vpc_imid = vpc_alloc_ifmap_id(tenant_uuid, vpc_name)
        tenant_imid = tenant_get_ifmap_id(tenant_uuid)

	self.publish_id_self_meta(vpc_imid)

        meta = str(Metadata('has', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = self.META_PERMS))
        self.publish_id_pair_meta(tenant_imid, vpc_imid, meta)

	return vpc_imid

    def vn_create(self, tenant_uuid, vpc_id, vn_name):
        vn_imid = vn_alloc_ifmap_id(tenant_uuid, vn_name)
	vpc_imid = vpc_get_ifmap_id(vpc_id)
 
        self.publish_id_self_meta(vn_imid)

        meta = str(Metadata('belongs-to', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = self.META_PERMS))
        self.publish_id_pair_meta(vpc_imid, vn_imid, meta)

	return vn_imid

    def subnets_set(self, tenant_uuid, vn_id, subnets):
        """
	subnets is a list updated in full by end-user agent
	at all operations
	"""

        vn_imid = vn_get_ifmap_id(vn_id)
        meta_subnets = ""
	for subnet in subnets:
	    meta_subnets += "<ct:subnet>"
	    if subnet.has_key('sn_ip_ver'):
	        meta_subnets += "  <ct:ip_ver> %s </ct:ip_ver>" \
		                               %(subnet['sn_ip_ver'])
	    if subnet.has_key('sn_ip_net'):
	        meta_subnets += "  <ct:ip_net> %s </ct:ip_net>" \
		                               %(subnet['sn_ip_net'])
	    if subnet.has_key('sn_ip6_net'):
	        meta_subnets += "  <ct:ip6_net> %s </ct:ip6_net>" \
		                                %(subnet['sn_ip6_net'])
	    if subnet.has_key('sn_prefix_len'):
	        meta_subnets += "  <ct:prefix_len> %s </ct:prefix_len>" \
		                                   %(subnet['sn_prefix_len'])
	    meta_subnets += "</ct:subnet>"

        mapclient = self._mapclient
        meta = str(Metadata('subnets', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_subnets))

        pubreq = PublishRequest(mapclient.get_session_id(),
                     str(PublishUpdateOperation(
                             id1 = str(Identity(
                                           name = vn_imid,
                                           type = "other",
                                           other_type = "extended")),
                             metadata = meta,
                             lifetime = 'forever')))
        result = mapclient.call('publish', pubreq)

    def subnets_get(self, tenant_uuid, vn_id):
        vn_imid = vn_get_ifmap_id(vn_id)

	mapclient = self._mapclient

        start_id = str(Identity(name = vn_imid, type = "other",
	                        other_type = "extended"))
        srch_req = SearchRequest(mapclient.get_session_id(), start_id,
	                        search_parameters = {
				    "match-links": "ct:subnets",
				    "result-filter": "ct:subnets"
				})
        result = mapclient.call('search', srch_req)

	soap_doc = lxml.etree.parse(StringIO.StringIO(result))

	#err_mch = soap_doc.xpath('/a:Envelope/a:Body/b:response/errorResult/errorString', namespaces = {'a': 'http://www.w3.org/2003/05/soap-envelope', 'b': 'http://www.trustedcomputinggroup.org/2010/IFMAP/2'})
	#if len(err_mch):
	#    # Subnets didn't exist already, search returned an error,
	#    # return empty list
	#    return []

        subnets_mch = soap_doc.xpath('/a:Envelope/a:Body/b:response/searchResult/resultItem/metadata/c:subnets/*',
	    namespaces = {
	        'a': 'http://www.w3.org/2003/05/soap-envelope',
		'b': 'http://www.trustedcomputinggroup.org/2010/IFMAP/2',
		'c': 'http://www.contrailsystems.com/2012/CT-METADATA/1'
            })

        if len(subnets_mch) == 0:
	    return []

        subnets_l = []
	subnet_d = {}
        for subnet_mch in subnets_mch:
            sn_mch = subnet_mch.xpath('//a:*',
	                 namespaces = {
		       'a': 'http://www.contrailsystems.com/2012/CT-METADATA/1'
                         })
            for elem in sn_mch:
	        if (re.sub("{.*}", "", elem.tag) == 'subnet') and subnet_d:
		    subnets_l.append(subnet_d)
		    subnet_d = {}
                if re.sub("{.*}", "", elem.tag) == 'ip_ver':
		    subnet_d['sn_ip_ver'] = elem.text
                if re.sub("{.*}", "", elem.tag) == 'ip_net':
		    subnet_d['sn_ip_net'] = elem.text
                if re.sub("{.*}", "", elem.tag) == 'ip6_net':
		    subnet_d['sn_ip6_net'] = elem.text
                if re.sub("{.*}", "", elem.tag) == 'prefix_len':
		    subnet_d['sn_prefix_len'] = elem.text

	    if subnet_d:
	        subnets_l.append(subnet_d)

	return subnets_l


    def security_group_create(self, tenant_uuid, vpc_id, sg_name):
        sg_imid = security_group_alloc_ifmap_id(tenant_uuid, sg_name)
	vpc_imid = vpc_get_ifmap_id(vpc_id)
 
        self.publish_id_self_meta(sg_imid)

        meta = str(Metadata('belongs-to', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = self.META_PERMS))
        self.publish_id_pair_meta(vpc_imid, sg_imid, meta)

	return sg_imid

    def policy_create(self, tenant_uuid, sg_id, pol_name):
        pol_imid = policy_alloc_ifmap_id(tenant_uuid, pol_name)
        sg_imid = security_group_get_ifmap_id(sg_id)
 
        self.publish_id_self_meta(pol_imid)
 
        meta = str(Metadata('belongs-to', '',
                       {'ifmap-cardinality':'singleValue'}, ns_prefix = "ct",
                       elements = meta_perms))
        self.publish_id_pair_meta(sg_imid, pol_imid, meta)

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
