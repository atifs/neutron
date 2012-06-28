# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

def get_vn_view_builder(req, version):
    #base_url = req.application_url
    #view_builder = {
    #    '1.0': ViewBuilder10,
    #}[version](base_url)
    #return view_builder
    return ViewBuilderVn10()

class ViewBuilderVn10(object):

    def build(self, vn_data):
        """Generates a VN entity"""
        return dict(id = vn_data['vn-id'])

def get_subnet_view_builder():
    #base_url = req.application_url
    #view_builder = {
    #    '1.0': ViewBuilder10,
    #}[version](base_url)
    #return view_builder
    return ViewBuilderSubnet10()

class ViewBuilderSubnet10(object):

    def build(self, subnet_data):
        """Generates a subnet entity"""
        return subnet_data
        
