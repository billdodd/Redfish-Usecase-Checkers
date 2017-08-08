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

from collections import OrderedDict
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
            d = r.json(object_pairs_hook=OrderedDict)
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


def modify_volume(rhost, uri, existing_vol_uri, existing_vol_data, hot_spare, results, validator, auth=None,
                  verify=True, nossl=False):
    logging.debug("modify_volume: Exercising Volumes uri {}".format(uri))
    logging.debug("modify_volume: auth = {}".format(auth))
    credentials = None
    if auth is not None:
        logging.debug("modify_volume: username = {}".format(auth.username))
        logging.debug("modify_volume: password = {}".format(auth.password))
        credentials = {"username": auth.username, "password": auth.password}

    # TODO: DELETE an existing volume
    # Notes:
    # If resource can never be deleted, a 405 is returned
    # If DELETE specifies a collection, a 405 is returned
    # 404 for bad request
    # 202 for accepted - should be a Location header for a Task to query
    # 200 for ok
    # Deleted resource representation (content) may be returned in response body
    if existing_vol_uri is not None:
        logging.debug("modify_volume: deleting existing volume at {}".format(existing_vol_uri))
        try:
            r = requests.delete(proto(nossl=nossl) + '://' + rhost + existing_vol_uri,
                                auth=auth, verify=verify, json=credentials)
            logging.debug("modify_volume: status code from DELETE volume = {}".format(r.status_code))
            logging.debug("modify_volume: response from DELETE volume = {}".format(r))
            if r.status_code == requests.codes.bad_request:
                logging.debug("modify_volume: response headers = {}".format(r.headers))
                logging.debug("modify_volume: response reason = {}".format(r.reason))
                logging.debug("modify_volume: response text = {}".format(r.text))
                logging.debug("modify_volume: response JSON = {}".format(r.json()))
            elif r.status_code == requests.codes.accepted:
                logging.debug("modify_volume: response headers = {}".format(r.headers))
                logging.debug("modify_volume: response text = {}".format(r.text))
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            log_error(results, "modify_volume", "Delete Volume",
                      "Exception received while tying to delete Volume at uri {}, error = {}"
                      .format(existing_vol_uri, e))
    else:
        logging.debug("modify_volume: no existing volume to delete")
    # TODO: POST to create volume
    payload = {"@odata.context": "/redfish/v1/$metadata#Systems/Members/5966929f180b1301003d47b6/Storage/Members/1/Volumes/$entity",
               "@odata.id": "/redfish/v1/Systems/5966929f180b1301003d47b6/Storage/1/Volumes/0",
               "@odata.type": "#Volume.1.0.2.Volume",
               "Oem": {},
               "Id": "0",
               "Description": "",
               "Name": "MAJEC",
               "Status": {"Health": "OK"},
               "CapacityBytes": 898313748480,
               "VolumeType": "StripedWithParity",
               "Identifiers":[],
               "BlockSizeBytes": 512,
               "Operations":
                   [
                       {"OperationName": "None", "PercentageComplete": 0}
                   ],
               "Links":
                   {"Drives@odata.count": 4,
                    "Drives": [
                        {"@odata.id": "/redfish/v1/Systems/5966929f180b1301003d47b6/Storage/1/Drives/0"},
                        {"@odata.id": "/redfish/v1/Systems/5966929f180b1301003d47b6/Storage/1/Drives/1"},
                        {"@odata.id": "/redfish/v1/Systems/5966929f180b1301003d47b6/Storage/1/Drives/2"},
                        {"@odata.id":"/redfish/v1/Systems/5966929f180b1301003d47b6/Storage/1/Drives/3"}
                    ]
                    }
               }
    """
    payload = {"Name": "RAID Usecase Checker Test Volume", "CapacityBytes": 256000000000, "VolumeType": "Mirrored"}
    try:
        r = requests.post(proto(nossl=nossl) + '://' + rhost + uri, json=payload, auth=auth, verify=verify)
        # Notes:
        # If POST not supported, a 405 is returned
        # Successful response status is 201 (Created)
        # Created resource URI shall be returned in Location header
        # Created resource representation (content) may be returned in response body
        logging.debug("modify_volume: status code from POST to create volume = {}".format(r.status_code))
        logging.debug("modify_volume: response from POST to create volume = {}".format(r))
        r.raise_for_status()
        if r.status_code == requests.codes.ok:
            d = r.json(object_pairs_hook=OrderedDict)
            logging.debug("modify_volume: response payload from create volume: {}".format(d))
        elif r.status_code == requests.codes.no_content:
            logging.debug("modify_volume: response from create volume had no content")
    except requests.exceptions.RequestException as e:
        log_error(results, "modify_volume", "Create Volume",
                  "Exception received while tying to create Volume in uri {}, error = {}".format(uri, e))
    """
    # TODO: PATCH to assign hot spare
    # TODO: GET to validate the created volume
    # TODO: DELETE to delete the volume


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
                      "'StorageControllers' resource not found from uri {}".format(store_uri))
        # Drives
        hot_spare = None
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
                    if hot_spare is None:
                        # save a drive_uri for use as a RAID hot spare
                        hot_spare = drive_uri
                else:
                    log_error(results, "process_storage", "Read Drive",
                              "Unable to read drive resource from uri {}".format(drive_uri))
            else:
                # inline case
                log_success(results, "Read Drive")
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
            else:
                log_error(results, "process_storage", "Read Volumes",
                          "Unable to read 'Volumes' resource from uri {}".format(volumes_uri))
            modify_volume(rhost, volumes_uri, existing_vol_uri, existing_vol_data, hot_spare, results, validator,
                          auth=auth, verify=verify, nossl=nossl)
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
            logging.debug("process_system: 'Storage' uri = {}".format(storage_uri))
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


def process_zone(zone, rhost, results, validator, auth=None, verify=True, nossl=False):
    zone_success, zone_name, zone_uri, zone_data = zone
    logging.debug("process_zone: zone name = {}, uri = {}, successfully read = {}"
                  .format(zone_name, zone_uri, zone_success))
    if zone_success and zone_data is not None:
        log_success(results, "Read ResourceZones Member")
        logging.debug("process_zone: zone data = {}".format(zone_data))
        if "@Redfish.CollectionCapabilities" in zone_data:
            log_success(results, "Read Zone CollectionCapabilities")
            cap_coll = zone_data.get("@Redfish.CollectionCapabilities")
            if "Capabilities" in cap_coll:
                log_success(results, "Read Zone Capabilities")
                capabilities = cap_coll.get("Capabilities")
                for capability in capabilities:
                    cap_uri = get_uri('CapabilitiesObject', capability)
                    if cap_uri is not None:
                        log_success(results, "Read Zone CapabilitiesObject")
                        logging.debug("process_zone: Resource Zone {}, 'CapabilitiesObject' uri = {}"
                                      .format(zone_name, cap_uri))
                        # TODO: get/process capability resource
                        print("process_zone: Resource Zone {}, 'CapabilitiesObject' uri = {}"
                              .format(zone_name, cap_uri))
                    else:
                        log_error(results, "process_zone", "Read Zone CapabilitiesObject",
                                  "'CapabilitiesObject' not found in '@Redfish.CollectionCapabilities' at uri {}"
                                  .format(zone_uri))
            else:
                log_error(results, "process_zone", "Read Zone Capabilities",
                          "'Capabilities' not found in '@Redfish.CollectionCapabilities' at uri {}".format(zone_uri))
        else:
            log_error(results, "process_zone", "Read Zone CollectionCapabilities",
                      "'@Redfish.CollectionCapabilities' not found at uri {}".format(zone_uri))
    else:
        log_error(results, "process_zone", "Read ResourceZones Member",
                  "Unable to get data payload for ResourceZones member {} at uri {}".format(zone_name, zone_uri))


def process_block(block, rhost, results, validator, auth=None, verify=True, nossl=False):
    block_success, block_name, block_uri, block_data = block
    logging.debug("process_block: block name = {}, uri = {}, successfully read = {}"
                  .format(block_name, block_uri, block_success))
    if block_success and block_data is not None:
        log_success(results, "Read ResourceBlocks Member")
        logging.debug("process_block: block data = {}".format(block_data))
        # Only interested in composable 'Storage' resources
        if 'Storage' in block_data:
            storage_list = block_data.get('Storage')
            if len(storage_list) > 0:
                for storage in storage_list:
                    storage_uri = get_uri(None, storage)
                    if storage_uri is not None:
                        log_success(results, "Read Block Storage URI")
                        logging.debug("process_block: Resource Block {}, 'Storage' uri = {}"
                                      .format(block_name, storage_uri))
                        # TODO: get/process Storage resource
                        print("process_block: Resource Block {}, 'Storage' uri = {}"
                              .format(block_name, storage_uri))
                    else:
                        log_error(results, "process_block", "Read Block Storage URI",
                                  "'Storage' URI not found in ResourceBlocks member at uri {}"
                                  .format(block_uri))
                if 'Links' in block_data:
                    log_success(results, "Read Block Links")
                    links = block_data.get('Links')
                    if 'Zones' in links:
                        zones = links.get('Zones')
                        if len(zones) > 0:
                            log_success(results, "Read links from Block to Zones")
                            for zone in zones:
                                zone_uri = get_uri(None, zone)
                                if zone_uri is not None:
                                    log_success(results, "Read Zone URI referenced from Block")
                                    logging.debug("process_block: Resource Block {} references Zone uri {}"
                                                  .format(block_name, zone_uri))
                                    # TODO: get/process Zones reference
                                    print("process_block: Resource Block {} references Zone uri {}"
                                          .format(block_name, zone_uri))
                                else:
                                    log_error(results, "process_block", "Read Zone URI referenced from Block",
                                              "Unable to read Zones URI in Links for ResourceBlocks member at uri {}"
                                              .format(block_uri))
                        else:
                            log_error(results, "process_block", "Read links from Block to Zones",
                                      "Zones resource empty in Links for ResourceBlocks member at uri {}"
                                      .format(block_uri))
                    else:
                        log_error(results, "process_block", "Read links from Block to Zones",
                                  "Zones resource not found in Links for ResourceBlocks member at uri {}"
                                  .format(block_uri))
                else:
                    log_error(results, "process_block", "Read Block Links",
                              "Links resource not found in ResourceBlocks member at uri {}"
                              .format(block_uri))

        else:
            logging.debug("process_block: No 'Storage' resources referenced from ResourceBlocks member {} at uri {}"
                          .format(block_name, block_uri))
    else:
        log_error(results, "process_block", "Read ResourceBlocks Member",
                  "Unable to get data payload for ResourceBlocks member {} at uri {}".format(block_name, block_uri))


def process_composition(composition, rhost, results, validator, auth=None, verify=True, nossl=False):
    comp_success, comp_name, comp_uri, comp_data = composition
    logging.debug("process_composition: composition name = {}, uri = {}, successfully read = {}"
                  .format(comp_name, comp_uri, comp_success))
    blocks_uri = get_uri('ResourceBlocks', comp_data)
    if blocks_uri is not None:
        logging.debug("process_composition: 'ResourceBlocks' uri = {}".format(blocks_uri))
        resource = get_resource(rhost, blocks_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
        blocks_success, blocks_name, blocks_uri, blocks_data = resource
        if blocks_success and blocks_data is not None:
            log_success(results, "Read ResourceBlocks")
            blocks_list = get_members(blocks_data, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
            for block in blocks_list:
                process_block(block, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
        else:
            log_error(results, "process_composition", "Read ResourceBlocks",
                      "Unable to read 'ResourceBlocks' resource from uri {}".format(blocks_uri))
    else:
        log_error(results, "process_composition", "Read ResourceBlocks", "'ResourceBlocks' uri not found")
    zones_uri = get_uri('ResourceZones', comp_data)
    if zones_uri is not None:
        logging.debug("process_composition: 'ResourceZones' uri = {}".format(zones_uri))
        resource = get_resource(rhost, zones_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
        zones_success, zones_name, zones_uri, zones_data = resource
        if zones_success and zones_data is not None:
            log_success(results, "Read ResourceZones")
            zones_list = get_members(zones_data, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
            for zone in zones_list:
                process_zone(zone, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
        else:
            log_error(results, "process_composition", "Read ResourceZones",
                      "Unable to read 'ResourceZones' resource from uri {}".format(zones_uri))
    else:
        log_error(results, "process_composition", "Read ResourceZones", "'ResourceZones' uri not found")


def get_service_root(rhost, auth=None, verify=True, nossl=False):
    """
    Get Service Root information
    """
    try:
        r = requests.get(proto(nossl=nossl) + '://' + rhost + '/redfish/v1', auth=auth, verify=verify)
        return r.json(object_pairs_hook=OrderedDict)
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

    # dictionary for requests kwargs
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

    results = Results("RAID Management Checker", service_root)
    if output_dir is not None:
        results.set_output_dir(output_dir)
    results.add_cmd_line_args(args_list)

    validator = SchemaValidation(rhost, service_root, results, auth=auth, verify=verify, nossl=nossl)

    if service_root is not None:
        log_success(results, "Read Service Root")
        # process CompositionService
        comp_uri = get_uri('CompositionService', service_root)
        if comp_uri is not None:
            composition = get_resource(rhost, comp_uri, results, validator, auth=auth, verify=verify, nossl=nossl)
            success, name, uri, data = composition
            if success and data is not None:
                log_success(results, "Read CompositionService")
                process_composition(composition, rhost, results, validator, auth=auth, verify=verify, nossl=nossl)
            else:
                log_error(results, "main", "Read CompositionService",
                          "Unable to read 'CompositionService' resource from target system {}".format(rhost))
        else:
            log_error(results, "main", "Read CompositionService",
                      "Unable to get 'CompositionService' URI from target system {}".format(rhost))
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
