# Copyright Notice:
# Copyright 2017 Distributed Management Task Force, Inc. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Usecase-Checkers/LICENSE.md

import argparse
import logging
import requests
import sys

# noinspection PyUnresolvedReferences
import toolspath

from collections import OrderedDict
from usecase.results import Results
# from usecase.validation import SchemaValidation


def proto(nossl=True):
    """
    :param nossl:
    :return: 'http' if nossl is True, otherwise 'https'
    """
    return 'http' if nossl else 'https'


def get_system(rhost, uri, auth=None, verify=True, nossl=False):
    # TODO: exception handling
    name = uri.split('/')[-1]
    logging.debug("get_system: Getting System with uri {}".format(uri))
    r = requests.get(proto(nossl=nossl) + '://' + rhost + uri, auth=auth, verify=verify)
    if r.status_code == requests.codes.ok:
        d = r.json(object_pairs_hook=OrderedDict)
        if d is not None:
            logging.debug("get_system: System resource: {}".format(d))
            # TODO: validate JSON
            return True, name, uri, d
        else:
            logging.error("get_system: No JSON content for {} found in response".format(uri))
    else:
        logging.error("get_system: Received unexpected response: {}".format(r))
    return False, name, uri, None


def get_systems(rhost, auth=None, verify=True, nossl=False):
    # TODO: exception handling
    sys_list = list()
    r = requests.get(proto(nossl=nossl) + '://' + rhost + '/redfish/v1/Systems', auth=auth, verify=verify)
    if r.status_code == requests.codes.ok:
        d = r.json(object_pairs_hook=OrderedDict)
        if d is not None:
            logging.debug("get_systems: Systems resource: {}".format(d))
            # TODO: validate JSON
            members = d.get('Members')
            if members is not None:
                for system in members:
                    uri = system.get('@odata.id')
                    if uri is not None:
                        sys_list.append(get_system(rhost, uri, auth=auth, verify=verify, nossl=nossl))
                    else:
                        logging.error("get_systems: No '@odata.id' found for system {}".format(system))
            else:
                logging.error("get_systems: No 'Members' found in /Systems")
        else:
            logging.error("get_systems: No JSON content for /Systems found in response")
    else:
        logging.error("get_systems: Received unexpected response: {}".format(r))
    return sys_list


def get_service_root(rhost, auth=None, verify=True, nossl=False):
    """
    Get Service Root information
    """
    # TODO: exception handling
    r = requests.get(proto(nossl=nossl) + '://' + rhost + '/redfish/v1', auth=auth, verify=verify)
    return r.json(object_pairs_hook=OrderedDict)


def log_results(results):
    """
    Log the results of the RAID management validation run
    """
    results.write_results()


def main(argv):
    """
    main
    """

    # Parse command-line args
    parser = argparse.ArgumentParser(description="Run a Redfish RAID management validation test")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity of output")
    parser.add_argument("-d", "--directory", help="subdirectory to write summary results.json file to")
    parser.add_argument("-r", "--rhost", help="target hostname or IP address with optional :port")
    parser.add_argument("-u", "--user", help="username for authentication to the target host")
    parser.add_argument("-p", "--password", help="password for authentication to the target host")
    # parser.add_argument("-t", "--token", help="security token for authentication to the target host")
    parser.add_argument('--nossl', action='store_true', help='use http instead of https')
    parser.add_argument('--nochkcert', action='store_true', help='ignore check for certificate')

    args = parser.parse_args()

    # Set up logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=log_level)

    args_list = [argv[0]]
    for name, value in vars(args).items():
        if name in ["password", "token"]:
            args_list.append(name + "=" + "********")
        else:
            args_list.append(name + "=" + str(value))
    logging.debug("command-line args after parsing: {}".format(args_list))

    rhost = args.rhost
    output_dir = args.directory
    auth = (args.user, args.password)
    # token = args.token
    nossl = args.nossl
    verify = not args.nochkcert

    sys_list = get_systems(rhost, auth=auth, verify=verify, nossl=nossl)
    for system in sys_list:
        success, name, uri, data = system
        logging.debug("system: name = {}, uri = {}, successfully read = {}".format(name, uri, success))
        # TODO: query drives and volumes

    # TODO: verify results

    # TODO: log results

    service_root = get_service_root(rhost, auth=auth, verify=verify, nossl=nossl)
    results = Results("RAID Management Checker", service_root)
    if output_dir is not None:
        results.set_output_dir(output_dir)
    results.add_cmd_line_args(args_list)

    log_results(results)
    exit(results.get_return_code())


if __name__ == "__main__":
    main(sys.argv)
