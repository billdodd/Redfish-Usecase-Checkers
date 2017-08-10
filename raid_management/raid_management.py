# Copyright Notice:
# Copyright 2017 Distributed Management Task Force, Inc. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Usecase-Checkers/LICENSE.md

import argparse
import logging
import requests
from requests.auth import HTTPBasicAuth
import sys

# noinspection PyUnresolvedReferences
import toolspath

from usecase.results import Results
from usecase.validation import SchemaValidation


def proto(nossl=True):
    """
    :param nossl:
    :return: 'http' if nossl is True, otherwise 'https'
    """
    return 'http' if nossl else 'https'


def get_uri(resource_name, data):
    if resource_name is None:
        resource = data
    elif resource_name in data:
        resource = data.get(resource_name)
    else:
        logging.warning("get_uri: Resource '{}' not found in data payload".format(resource_name))
        return None
    if '@odata.id' in resource:
        return resource.get('@odata.id')
    else:
        logging.warning("get_uri: '@odata.id' not found in resource '{}'".format(resource_name))
        return None


def log_success(results, test_name):
    """
    Add success result to Results object

    :param results: instance of Results object to update
    :param test_name: name of the test that passed
    """
    results.update_test_results(test_name, 0, None)


def log_error(results, function_name, test_name, message):
    """
    Add error result to Results object and log error via python logging

    :param results: instance of Results object to update
    :param function_name: name of the function generating the error
    :param test_name: name of the test that failed
    :param message: error message for the failure
    """
    logging.error(function_name + ": " + message)
    results.update_test_results(test_name, 1, message)


def get_resource(rhost, uri, results, validator, auth=None, verify=True, nossl=False):
    # TODO: return tuple: what are needed values to return? Include error message?
    name = uri.split('/')[-1]
    logging.debug("get_resource: Getting {} resource with uri {}".format(name, uri))
    try:
        r = requests.get(proto(nossl=nossl) + '://' + rhost + uri, auth=auth, verify=verify)
        if r.status_code == requests.codes.ok:
            d = r.json()
            if d is not None:
                log_success(results, "Read Resource")
                logging.debug("get_resource: {} resource: {}".format(name, d))
                schema = validator.get_json_schema(d)
                rc, msg, skipped = 0, None, False
                if schema is not None:
                    rc, msg = validator.validate_json(d, schema)
                else:
                    skipped = True
                results.update_test_results("Schema validation", rc, msg, skipped=skipped)
                return True, name, uri, d
            else:
                log_error(results, "get_resource", "Read Resource",
                          "No JSON content for {} found in response".format(uri))
        else:
            log_error(results, "get_resource", "Read Resource",
                      "Received unexpected response for resource {}: response = {}".format(name, r))
    except requests.exceptions.RequestException as e:
        log_error(results, "get_resource", "Read Resource",
                  "Exception received while tying to fetch uri {}, error = {}".format(uri, e))
    return False, name, uri, None


def get_members(data, rhost, results, validator, auth=None, verify=True, nossl=False):
    member_list = list()
    if data is not None:
        logging.debug("get_members: Resource: {}".format(data))
        members = data.get('Members')
        if members is not None:
            log_success(results, "Read Members")
            for member in members:
                uri = member.get('@odata.id')
                if uri is not None:
                    log_success(results, "Read @odata.id for Member")
                    member_list.append(get_resource(rhost, uri, results, validator, auth=auth, verify=verify,
                                                    nossl=nossl))
                else:
                    log_error(results, "get_members", "Read @odata.id for Member",
                              "No '@odata.id' found for member")
        else:
            log_error(results, "get_members", "Read Members", "No 'Members' found in resource")
    else:
        log_error(results, "get_members", "Read Members", "No JSON content for resource found in response")
    return member_list


def delete_volume(rhost, volumes_uri, existing_vol_uri, existing_vol_data, drive_list, results, validator, auth=None,
                  verify=True, nossl=False):
    logging.debug("delete_volume: Volumes uri {}, attempting to delete volume {}".format(volumes_uri, existing_vol_uri))

    # TODO: Need boolean confirming delete operation OK?

    # TODO: Why do we need to specify creds in the body? Figure this out.
    credentials = None
    if auth is not None:
        logging.debug("delete_volume: username = {}".format(auth.username))
        logging.debug("delete_volume: password = {}".format('********'))
        credentials = {"username": auth.username, "password": auth.password}

    if existing_vol_uri is not None:
        logging.debug("delete_volume: deleting existing volume at {}".format(existing_vol_uri))
        try:
            r = requests.delete(proto(nossl=nossl) + '://' + rhost + existing_vol_uri,
                                auth=auth, verify=verify, json=credentials)
            logging.debug("delete_volume: status code from DELETE volume = {}".format(r.status_code))
            logging.debug("delete_volume: response from DELETE volume = {}".format(r))
            logging.debug("delete_volume: response text from DELETE volume = {}".format(r.text))
            logging.debug("delete_volume: response headers from DELETE volume = {}".format(r.headers))
            if r.status_code == requests.codes.ok:
                log_success(results, "Delete Volume")
            elif r.status_code == requests.codes.accepted:
                # async case
                if 'Location' in r.headers:
                    log_success(results, "Delete Volume")
                    task = r.headers.get('Location')
                    # TODO: poll task until it is complete
                else:
                    log_error(results, "delete_volume", "Delete Volume",
                              "DELETE returned ACCEPTED, but Location header missing for task, volumes uri {}"
                              .format(existing_vol_uri))
            elif r.status_code == requests.codes.method_not_allowed:
                logging.debug("delete_volume: DELETE not supported on volume uri {}".format(existing_vol_uri))
            elif r.status_code == requests.codes.bad_request:
                logging.debug("delete_volume: BAD REQUEST, response reason = {}".format(r.reason))
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            log_error(results, "delete_volume", "Delete Volume",
                      "Exception received while tying to delete Volume at uri {}, error = {}"
                      .format(existing_vol_uri, e))
    else:
        logging.debug("delete_volume: no existing volume to delete")


def create_volume(rhost, volumes_uri, existing_vol_uri, existing_vol_data, drive_list, results, validator, auth=None,
                  verify=True, nossl=False):
    logging.debug("create_volume: Exercising Volumes uri {}".format(volumes_uri))

    # TODO: Why do we need to specify creds in the body? Figure this out.
    credentials = None
    if auth is not None:
        logging.debug("create_volume: username = {}".format(auth.username))
        logging.debug("create_volume: password = {}".format('********'))
        credentials = {"username": auth.username, "password": auth.password}

    volume_type = "Mirrored"
    # volume_type = "StripedWithParity"
    capacity_bytes = 256000000000
    payload = {"Name": "RAID Usecase Checker Test Volume",
               "CapacityBytes": capacity_bytes,
               "VolumeType": volume_type}
    # TODO: option to specify drives to include in the volume (otherwise let Redfish choose the drives)

    new_vol_uri = None
    try:
        r = requests.post(proto(nossl=nossl) + '://' + rhost + volumes_uri, json=payload, auth=auth, verify=verify)
        logging.debug("create_volume: status code from POST to create volume = {}".format(r.status_code))
        logging.debug("create_volume: response from POST to create volume = {}".format(r))
        logging.debug("create_volume: response text from POST to create volume = {}".format(r.text))
        logging.debug("create_volume: response headers from POST to create volume = {}".format(r.headers))
        if r.status_code == requests.codes.created:
            if 'Location' in r.headers:
                new_vol_uri = r.headers.get('Location')
            else:
                log_error(results, "create_volume", "Create Volume",
                          "POST returned CREATED as expected, but Location header missing, Volumes uri {}"
                          .format(volumes_uri))
        elif r.status_code == requests.codes.accepted:
            # async case
            if 'Location' in r.headers:
                task = r.headers.get('Location')
                # TODO: poll task until it is complete
            else:
                log_error(results, "create_volume", "Create Volume",
                          "POST returned ACCEPTED, but Location header missing for task, Volumes uri {}"
                          .format(volumes_uri))
        elif r.status_code == requests.codes.method_not_allowed:
            logging.debug("create_volume: POST not supported on volume uri {}".format(volumes_uri))
        elif r.status_code == requests.codes.bad_request:
            logging.debug("create_volume: BAD REQUEST, response reason = {}".format(r.reason))
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        log_error(results, "create_volume", "Create Volume",
                  "Exception received while tying to create Volume in uri {}, error = {}".format(volumes_uri, e))

    # TODO: do a GET on the new volume to confirm it was created

    return new_vol_uri


def process_storage(storage, rhost, results, validator, auth=None, verify=True, nossl=False):
    store_success, store_name, store_uri, store_data = storage
    logging.debug("process_storage: system name = {}, uri = {}, successfully read = {}"
                  .format(store_name, store_uri, store_success))
    if store_success and store_data is not None:
        log_success(results, "Read Storage Member")
        # StorageControllers
        controllers = store_data.get('StorageControllers')
        logging.debug("process_storage: 'StorageControllers' = {}".format(controllers))
        if controllers is not None:
            log_success(results, "Read Controllers")
            for controller in controllers:
                logging.debug("process_storage: controller = {}".format(controller))
                if '@odata.id' in controller:
                    controller_uri = controller.get('@odata.id')
                    if '#' in controller_uri and '@odata.type' in controller:
                        # inline case
                        ctrl_success, ctrl_data = True, controller
                    else:
                        # follow uri reference case
                        resource = get_resource(rhost, controller_uri, results, validator, auth=auth, verify=verify,
                                                nossl=nossl)
                        ctrl_success, ctrl_name, ctrl_uri, ctrl_data = resource
                    if ctrl_success and ctrl_data is not None:
                        log_success(results, "Read Controller")
                    else:
                        log_error(results, "process_storage", "Read Controller",
                                  "Unable to read controller resource from uri {}".format(controller_uri))
                else:
                    # inline case
                    log_success(results, "Read Controller")
        else:
            log_error(results, "process_storage", "Read Controllers",
                      "'StorageControllers' resource not found for storage {} at uri {}".format(store_name, store_uri))
        # Drives
        drive_list = list()
        if 'Drives' in store_data:
            log_success(results, "Read Drives")
            drives = store_data.get('Drives')
            logging.debug("process_storage: 'Drives' = {}".format(drives))
            for drive in drives:
                logging.debug("process_storage: drive = {}".format(drive))
                if '@odata.id' in drive:
                    drive_uri = drive.get('@odata.id')
                    if '#' in drive_uri and '@odata.type' in drive:
                        # inline case
                        drive_success, drive_data = True, drive
                    else:
                        # follow uri reference case
                        resource = get_resource(rhost, drive_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
                        drive_success, drive_name, drive_uri, drive_data = resource
                    if drive_success and drive_data is not None:
                        log_success(results, "Read Drive")
                        logging.debug("process_storage: appending drive to drive_list, uri = {}".format(drive_uri))
                        drive_list.append(drive_uri)
                    else:
                        log_error(results, "process_storage", "Read Drive",
                                  "Unable to read drive resource from uri {}".format(drive_uri))
                else:
                    # inline case
                    log_success(results, "Read Drive")
        else:
            log_error(results, "process_storage", "Read Drives",
                      "'Drives' resource not found for storage {} at uri {}".format(store_name, store_uri))
        # Volumes
        existing_vol_uri, existing_vol_data = None, None
        volumes_uri = get_uri('Volumes', store_data)
        if volumes_uri is not None:
            logging.debug("process_storage: 'Volumes' uri = {}".format(volumes_uri))
            resource = get_resource(rhost, volumes_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
            vols_success, vols_name, vols_uri, vols_data = resource
            if vols_success and vols_data is not None:
                log_success(results, "Read Volumes")
                vols_list = get_members(vols_data, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
                for volume in vols_list:
                    vol_success, vol_name, vol_uri, vol_data = volume
                    logging.debug("process_storage: Volume uri = {}".format(vol_uri))
                    logging.debug("process_storage: Volume data = {}".format(vol_data))
                    if vol_success and vol_data is not None:
                        if existing_vol_uri is None:
                            # save an existing volume uri so we can delete it before creating new one
                            existing_vol_uri = vol_uri
                            existing_vol_data = vol_data
                # Delete existing volume first
                delete_volume(rhost, volumes_uri, existing_vol_uri, existing_vol_data, drive_list, results, validator,
                              auth=auth, verify=verify, nossl=nossl)
                # Create new volume
                new_vol_uri = create_volume(rhost, volumes_uri, existing_vol_uri, existing_vol_data, drive_list,
                                            results, validator, auth=auth, verify=verify, nossl=nossl)
                # Patch new volume with hot spare drive
                # TODO: patch_volume()
                # Delete newly created volume
                delete_volume(rhost, volumes_uri, new_vol_uri, None, drive_list, results, validator,
                              auth=auth, verify=verify, nossl=nossl)
            else:
                log_error(results, "process_storage", "Read Volumes",
                          "Unable to read 'Volumes' resource from uri {}".format(volumes_uri))
        else:
            log_error(results, "process_storage", "Read Volumes", "'Volumes' uri not found for storage {} at uri {}"
                      .format(store_name, store_uri))
    else:
        log_error(results, "process_storage", "Read Storage Member",
                  "Unable to get data payload for storage {} at uri {}".format(store_name, store_uri))


def process_system(system, rhost, results, validator, auth=None, verify=True, nossl=False):
    sys_success, sys_name, sys_uri, sys_data = system
    logging.debug("process_system: system name = {}, uri = {}, successfully read = {}"
                  .format(sys_name, sys_uri, sys_success))
    if sys_success and sys_data is not None:
        log_success(results, "Read System")
        storage_uri = get_uri('Storage', sys_data)
        if storage_uri is not None:
            logging.debug("process_system: Storage uri = {}".format(storage_uri))
            resource = get_resource(rhost, storage_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
            store_success, store_name, store_uri, store_data = resource
            if store_success and store_data is not None:
                log_success(results, "Read Storage")
                storage_list = get_members(store_data, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
                for storage in storage_list:
                    process_storage(storage, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
            else:
                log_error(results, "process_system", "Read Storage",
                          "Unable to read 'Storage' resource from system uri {}".format(sys_uri))
        else:
            log_error(results, "process_system", "Read Storage", "'Storage' uri not found")
    else:
        log_error(results, "process_system", "Read System",
                  "Unable to get data payload for system {} at uri {}".format(sys_name, sys_uri))


def get_service_root(rhost, auth=None, verify=True, nossl=False):
    """
    Get Service Root information
    """
    try:
        r = requests.get(proto(nossl=nossl) + '://' + rhost + '/redfish/v1', auth=auth, verify=verify)
        return r.json()
    except requests.exceptions.RequestException as e:
        logging.error("get_service_root: Exception received while tying to fetch service root, error = {}".format(e))
    return {}


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
    parser = argparse.ArgumentParser(description='Run a Redfish RAID management validation test')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='increase verbosity of output')
    parser.add_argument('-d', '--directory', help='subdirectory to write summary results.json file to')
    parser.add_argument('-r', '--rhost', help='target hostname or IP address with optional :port')
    parser.add_argument('-u', '--user', help='username for authentication to the target host')
    parser.add_argument('-p', '--password', help='password for authentication to the target host')
    # parser.add_argument('-t', '--token', help='security token for authentication to the target host')
    parser.add_argument('--nossl', action='store_true', help='use http instead of https')
    parser.add_argument('--nochkcert', action='store_true', help='disable certificate verification check')
    parser.add_argument('--ca-bundle', help='path to Certificate Authority bundle file or directory')
    parser.add_argument('--http-proxy', help='URL for the HTTP proxy')
    parser.add_argument('--https-proxy', help='URL for the HTTPS proxy')

    args = parser.parse_args()

    # Set up logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(stream=sys.stderr, level=log_level)

    # Process command-line args
    args_list = [argv[0]]
    for name, value in vars(args).items():
        if name in ['password', 'token']:
            args_list.append(name + '=' + '********')
        else:
            args_list.append(name + '=' + str(value))
    logging.debug('main: command-line args after parsing: {}'.format(args_list))

    rhost = args.rhost
    output_dir = args.directory
    auth = None
    if args.user is not None or args.password is not None:
        auth = HTTPBasicAuth(args.user, args.password)
    # token = args.token
    nossl = args.nossl
    verify = True
    if args.nochkcert:
        verify = False
    elif args.ca_bundle is not None:
        verify = args.ca_bundle

    # Create dictionary for requests kwargs
    requests_dict = {'auth': auth, 'verify': verify, 'headers': {'OData-Version': '4.0'}}
    if args.http_proxy is not None or args.https_proxy is not None:
        if args.http_proxy is None:
            proxy_dict = {'https': args.https_proxy}
        elif args.https_proxy is None:
            proxy_dict = {'http': args.http_proxy}
        else:
            proxy_dict = {'http': args.http_proxy, 'https': args.https_proxy}
        requests_dict.update({'proxies': proxy_dict})
    logging.debug('main: requests kwargs dictionary: {}'.format(requests_dict))

    service_root = get_service_root(rhost, auth=auth, verify=verify, nossl=nossl)

    # Initialize Results instance
    results = Results("RAID Management Checker", service_root)
    if output_dir is not None:
        results.set_output_dir(output_dir)
    results.add_cmd_line_args(args_list)

    # Initialize JSON schema validation instance
    validator = SchemaValidation(rhost, service_root, results, auth=auth, verify=verify, nossl=nossl)

    if service_root is not None:
        log_success(results, "Read Service Root")
        # process Systems
        systems_uri = get_uri('Systems', service_root)
        if systems_uri is not None:
            systems = get_resource(rhost, systems_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
            success, name, uri, data = systems
            if success and data is not None:
                log_success(results, "Read Systems")
                sys_list = get_members(data, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
                for system in sys_list:
                    process_system(system, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
            else:
                log_error(results, "main", "Read Systems",
                          "Unable to read 'Systems' resource from target system {}".format(rhost))
        else:
            log_error(results, "main", "Read Systems",
                      "Unable to get 'Systems' URI from target system {}".format(rhost))
    else:
        log_error(results, "Read Service Root", "main",
                  "Unable to retrieve Service Root from target system {}".format(rhost))

    log_results(results)
    exit(results.get_return_code())


if __name__ == "__main__":
    main(sys.argv)
