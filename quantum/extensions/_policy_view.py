# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Contrail Systems, Inc.
#

"""
.. attention:: Fix the license string
"""

def get_view_builder(req, version):
    #base_url = req.application_url
    #view_builder = {
    #    '1.0': ViewBuilder10,
    #}[version](base_url)
    #return view_builder
    return ViewBuilder10()

class ViewBuilder10(object):

    def build(self, sg_data):
        """Generates a policy entity"""
        return dict(id=sg_data['policy-id'])
