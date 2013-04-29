#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Neworks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# If ../quantum/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...

import sys

from oslo.config import cfg

from quantum.common import config
from quantum import service


def main(args_str = None):
    # the configuration will be read into the cfg.CONF global data structure
    if not args_str:
        args_list = sys.argv[1:]
    else:
        args_list = args_str.split()
    config.parse(args_list)

    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.quantum/, ~/, /etc/quantum/, /etc/) and"
                   " the '--config-file' option!"))
    try:
        quantum_service = service.serve_wsgi(service.QuantumApiService)
        quantum_service.wait()
    except RuntimeError, e:
        sys.exit(_("ERROR: %s") % e)


if __name__ == "__main__":
    main()
