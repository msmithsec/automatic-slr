#!/usr/bin/env python3
# Copyright (c) 2020
# Author: Matt Smith <msmith@paloaltonetworks.com>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

__author__ = "Matt Smith <msmith@paloaltonetworks.com>"
__version__ = "1.2.0"
__license__ = "GPLv3"

import argparse
import configparser
import json
import logging
import logzero
import os
import requests
import sys
import threading
import time
import urllib3
import xml.etree.ElementTree as ET

from logzero import logger
from requests.exceptions import ConnectionError, Timeout


def main(args):
    logger.info(
        'Palo Alto Networks Automatic SLR Generator (' + __version__ + ')')
    logger.info('--------------------------------------------------')

    # Output arguments
    logger.debug(args)

    # Output current logging level
    if args.verbose is True:
        logger.info('Logging level is set to: DEBUG')
    else:
        logger.info('Logging level is set to: INFO')

    # Debug output parsed command line arguments
    file_config = args.config
    file_log = args.log
    logger.debug('Setting configuration file to: ' + file_config)
    logger.debug('Setting log file to: ' + file_log)

    configuration = read_configuration(file_config)

    # Enable/Disable SSL/TLS verification
    if 'true' in configuration['system_verify']:
        logger.info('SSL/TLS certification verification is enabled')
        tls_verify = True
    else:
        logger.warning('SSL/TLS certification verification is disabled!')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        tls_verify = False

    model = panos_type_check(
        configuration['target_address'], configuration['target_api_key'], configuration['system_panostimeout'], tls_verify)
    logger.debug('Got ' + str(model) + ' back from panos_type_check()')

    if 'Panorama' in model:
        logger.info('Panorama detected, fetching list of connected devices...')
        connected_devices = panorama_get_devices(
            configuration['target_address'], configuration['target_api_key'], configuration['system_panostimeout'], tls_verify)

        # Loop through all connected devices and generate stats dump file
        threads = []
        for d_serial, d_entry in connected_devices.items():
            target_serial = d_serial

            # for _ is used to designate throwaway variable
            for _ in d_entry:
                target_hostname = d_entry['hostname']
                target_ip = d_entry['ip-address']

            logger.info('Attempting to generate stats-dump file for: ' +
                        target_hostname + ' (' + target_ip + ' | ' + target_serial + ')')

            # Create a thread for each device
            t = threading.Thread(target=mt_stats_generate, args=[
                                 target_ip, configuration['target_api_key'], configuration['system_panostimeout'], tls_verify, configuration])
            t.start()
            threads.append(t)

        for thread in threads:
            thread.join()

    else:
        logger.info(
            str(model) + ' detected, attempting to generate stats dump...')

        target_address = configuration['target_address']
        api_key = configuration['target_api_key']
        timeout = configuration['system_panostimeout']

        job = stats_generate(target_address, api_key, timeout, tls_verify)

        if job is False:
            logger.error('Received error from stats_generate() for ' +
                         target_address + ', check logs for debug information')
        else:
            logger.debug('Calling stats_download() for: ' + target_address)
            stats_file = stats_download(
                target_address, api_key, job, timeout, tls_verify)

            if stats_file is False:
                logger.error('Received error from stats_download() for ' +
                             target_address + ', check logs for debug information')
            else:
                logger.debug('Calling upload_stats() for: ' + target_address)
                upload = upload_stats(
                    target_address, stats_file, configuration, tls_verify)

                if upload is True:
                    logger.info(
                        'Successfully uploaded stats dump to Palo Alto Networks for ' + target_address)
                else:
                    logger.error(
                        'Error encountered uploading to Palo Alto Networks for ' + target_address)
                    logger.error('Check logs for debug information...')


def read_configuration(file_config):
    logger.debug('Function called with parameter file_config = ' + file_config)

    # Setup configuration handler
    configuration = configparser.ConfigParser(allow_no_value=True)

    # Check if configuration file exists
    try:
        logger.info('Checking if ' + file_config + ' exists...')
        file = os.path.isfile(file_config)

        if file is True:
            logger.info(
                'Configuration file exists, attempting to read configuration file...')
            configuration.read(file_config)
        else:
            raise Exception('Configuration file does not exist')

    except Exception as e:
        logger.exception(e)
        sys.exit(1)

    # Setup our Python dictionary to store configuration values
    conf = {}

    # Map configuration values for the target device
    conf['target_address'] = configuration.get('target', 'address')
    conf['target_api_key'] = configuration.get('target', 'panos_key')

    # Map configuration values for the SLR attributes
    conf['slr_preparedby'] = configuration.get('SLR', 'prepared_by')
    conf['slr_requestedby'] = configuration.get('SLR', 'requested_by')
    conf['slr_sendto'] = configuration.get('SLR', 'send_to')
    conf['slr_csp'] = configuration.get('SLR', 'csp_key')
    conf['slr_accountname'] = configuration.get('SLR', 'account_name')
    conf['slr_industry'] = configuration.get('SLR', 'industry')
    conf['slr_country'] = configuration.get('SLR', 'country')
    conf['slr_region'] = configuration.get('SLR', 'geographic_region')
    conf['slr_deploymentlocation'] = configuration.get(
        'SLR', 'deployment_location')
    conf['slr_language'] = configuration.get('SLR', 'language')

    # Map configuration values for general system behaviour
    conf['system_version'] = __version__
    conf['system_panostimeout'] = configuration.get('system', 'panos_timeout')
    conf['system_uploadtimeout'] = configuration.get(
        'system', 'upload_timeout')
    conf['system_verify'] = configuration.get('system', 'verify')

    # Output mapping results to the command line
    logger.info(' [Target] Address                = ' + conf['target_address'])
    logger.debug('[Target] API Key                = ' + conf['target_api_key'])
    logger.info(' [SLR] Prepared By               = ' + conf['slr_preparedby'])
    logger.info(' [SLR] Requested By              = ' +
                conf['slr_requestedby'])
    logger.info(' [SLR] Send To                   = ' + conf['slr_sendto'])
    logger.debug('[SLR] CSP Key                   = ' + conf['slr_csp'])
    logger.info(' [SLR] Account                   = ' +
                conf['slr_accountname'])
    logger.info(' [SLR] Industry                  = ' + conf['slr_industry'])
    logger.info(' [SLR] Country                   = ' + conf['slr_country'])
    logger.info(' [SLR] Geographic Region         = ' + conf['slr_region'])
    logger.info(' [SLR] Deployment Location       = ' +
                conf['slr_deploymentlocation'])
    logger.info(' [SLR] Language                  = ' + conf['slr_language'])
    logger.info(' [System] Version                = ' + conf['system_version'])
    logger.info(' [System] PANOS Timeout          = ' +
                conf['system_panostimeout'] + ' seconds')
    logger.info(' [System] Upload Timeout         = ' +
                conf['system_uploadtimeout'] + ' seconds')
    logger.info(' [System] Verify TLS Certificate = ' + conf['system_verify'])

    return conf


def panos_type_check(target_address, api_key, timeout, tls_verify):
    logger.debug('Function called with following parameters:')
    logger.debug('Target Device                    = ' + target_address)
    logger.debug('PANOS API Key                    = ' + api_key)
    logger.debug('PANOS API Timeout                = ' + timeout)
    logger.debug('SSL/TLS Certificate Verification = ' + str(tls_verify))
    logger.info('Checking if target system is Panorama...')

    uri = 'https://' + target_address + \
        '/api/?type=op&cmd=<show><system><info></info></system></show>&key=' + api_key
    logger.debug('Constructed URI: ' + uri)

    # Run the API request against the target
    try:
        response = requests.get(uri, timeout=int(timeout), verify=tls_verify)
        logger.debug(response.text)
        logger.debug(response.status_code)

        # If response was successful
        if response.status_code is 200:
            logger.info('Success status code received, parsing response...')

            # Parse XML response
            xml = ET.fromstring(response.content)

            # No error detected in XML response, proceed...
            logger.info('XML Response Status: ' + xml.attrib['status'])

            # Get information of target device
            device_name = str(xml.find('./result/system/hostname').text)
            device_mgmt_ip = str(xml.find('./result/system/ip-address').text)
            device_model = str(xml.find('./result/system/model').text)
            device_serial = str(xml.find('./result/system/serial').text)
            device_software = str(xml.find('./result/system/sw-version').text)

            if 'Panorama' in device_model:
                device_public_ip = str(
                    xml.find('./result/system/public-ip-address').text)
            else:
                pass

            logger.info('Platform Model:            ' + device_model)
            logger.info('Platform Hostname:         ' + device_name)

            if 'Panorama' in device_model:
                logger.info('Platform Management IP:    ' +
                            device_mgmt_ip + ' (Public: ' + device_public_ip + ')')
            else:
                logger.info('Platform Management IP:    ' + device_mgmt_ip)

            logger.info('Platform Serial Number:    ' + device_serial)
            logger.info('Platform Software Release: ' + device_software)

            return device_model

        # Response was not successful...
        else:
            raise Exception('Recieved error back from API: ' + response.text)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)


def panorama_get_devices(target_address, api_key, timeout, tls_verify):
    logger.debug('Function called with following parameters:')
    logger.debug('Target Device                    = ' + target_address)
    logger.debug('PANOS API Key                    = ' + api_key)
    logger.debug('PANOS API Timeout                = ' + timeout)
    logger.debug('SSL/TLS Certificate Verification = ' + str(tls_verify))
    logger.info('Checking if target system is Panorama...')

    uri = 'https://' + target_address + \
        '/api/?type=op&cmd=<show><devices><connected></connected></devices></show>&key=' + api_key
    logger.debug('Constructed URI: ' + uri)

    # Run the API request against the target
    try:
        response = requests.get(uri, timeout=int(timeout), verify=tls_verify)
        logger.debug(response.text)
        logger.debug(response.status_code)

        # If response was successful
        if response.status_code is 200:
            logger.info('Success status code received, parsing response...')

            # Parse XML response
            xml = ET.fromstring(response.content)

            # No error detected in XML response, proceed...
            logger.info('XML Response Status: ' + xml.attrib['status'])

            connected_devices = {}

            for entry in xml.findall('./result/devices/entry'):
                device_serial = str(entry.get('name'))
                device_hostname = str(entry.find('hostname').text)
                device_ip = str(entry.find('ip-address').text)
                device_model = str(entry.find('model').text)
                device_software = str(entry.find('sw-version').text)
                logger.info('Received: ' + device_hostname + ' (' + device_ip + ' | ' +
                            device_model + ' | ' + device_serial + ' | ' + device_software + ')')
                logger.debug('Creating dictionary entry for ' +
                             device_hostname + ' (' + device_serial + ')')

                connected_devices[device_serial] = {
                    "hostname": device_hostname,
                    "ip-address": device_ip,
                    "model": device_model,
                    "serial": device_serial,
                    "software": device_software
                }

            logger.debug('Constructed dictionary: ' + str(connected_devices))
            logger.info('Found ' + str(len(connected_devices)) +
                        ' connected devices')

            # Loop through dictionary items and output
            for d_serial, d_entry in connected_devices.items():
                logger.info('--------------------------------')
                logger.info('Serial Number: ' + d_serial)

                # Get key:pair values from nested dictionary
                for key in d_entry:
                    logger.info('> ' + key + ' : ' + d_entry[key])
            logger.info('--------------------------------')

            return connected_devices

        # Response was not successful...
        else:
            raise Exception('Recieved error back from API: ' + response.text)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)


def mt_stats_generate(target_address, api_key, timeout, tls_verify, configuration):
    logger.debug('[' + target_address + '] Thread initialised for ' + target_address +
                 ' with thread ID: ' + str(threading.current_thread().ident))

    logger.debug(
        '[' + target_address + '] Calling stats_generate() for: ' + target_address)
    job = stats_generate(target_address, api_key, timeout, tls_verify)

    if job is False:
        logger.error('[' + target_address + '] Received error from stats_generate() for ' +
                     target_address + ', check logs for debug information')
    else:
        logger.debug(
            '[' + target_address + '] Calling stats_download() for: ' + target_address)
        stats_file = stats_download(
            target_address, api_key, job, timeout, tls_verify)

        if stats_file is False:
            logger.error('[' + target_address + '] Received error from stats_download() for ' +
                         target_address + ', check logs for debug information')
        else:
            logger.debug(
                '[' + target_address + '] Calling upload_stats() for: ' + target_address)
            upload = upload_stats(
                target_address, stats_file, configuration, tls_verify)

            if upload is True:
                logger.info(
                    '[' + target_address + '] Successfully uploaded stats dump to Palo Alto Networks for ' + target_address)
            else:
                logger.error(
                    '[' + target_address + '] Error encountered uploading to Palo Alto Networks for ' + target_address)
                logger.error(
                    '[' + target_address + '] Check logs for debug information...')


def stats_generate(target_address, api_key, timeout, tls_verify):
    logger.debug(
        '[' + target_address + '] Function called with following parameters:')
    logger.debug('[' + target_address +
                 '] Target Device                    = ' + target_address)
    logger.debug(
        '[' + target_address + '] PANOS API Key                    = ' + api_key)
    logger.debug(
        '[' + target_address + '] PANOS API Timeout                = ' + timeout)
    logger.debug('[' + target_address +
                 '] SSL/TLS Certificate Verification = ' + str(tls_verify))
    logger.info(
        '[' + target_address + '] Generating stats dump for: ' + target_address)

    uri = 'https://' + target_address + \
        '/api/?type=export&category=stats-dump&key=' + api_key
    logger.debug('[' + target_address + '] Constructed URI: ' + uri)

    logger.info(
        '[' + target_address + '] Initiating statistics dump generation on target device: ' + target_address)

    try:
        try:
            response = requests.get(
                uri, timeout=int(timeout), verify=tls_verify)
        except (requests.exceptions.ConnectionError) as e:
            logger.error(
                '[' + target_address + '] Encountered Connection Error and could not connect to: ' + target_address)
            logger.error(e)
            response = None
        except (requests.exceptions.Timeout) as e:
            logger.error(
                '[' + target_address + '] Encountered Network Timeout and could not connect to: ' + target_address)
            logger.error(e)
            response = None

        if response is not None:
            logger.debug(response.text)
            logger.debug(response.status_code)

            # If response was successful
            if response.status_code is 200:
                logger.info(
                    '[' + target_address + '] Success status code received, parsing response...')

                # Parse XML response
                xml = ET.fromstring(response.content)

                # No error detected in XML response, proceed...
                logger.info(
                    '[' + target_address + '] XML Response Status: ' + xml.attrib['status'])

                # Retireve Job ID
                job = xml.find('./result/job').text
                logger.info('[' + target_address + '] Received Job ID: ' + job)

                # Wait for the statistics dump generation job to finish
                status = stats_check(
                    target_address, api_key, job, timeout, tls_verify)

                if status is True:
                    logger.info(
                        '[' + target_address + '] Statistics dump finished generating')
                    return job
                else:
                    logger.error(
                        '[' + target_address + '] Statistics dump failed to generate, please consult the log files in debug mode')

            # Response was not successful...
            else:
                logger.error(
                    '[' + target_address + '] Recieved error back from API: ' + response.text)
                return False
        else:
            return False

    except Exception as e:
        logger.exception(e)
        sys.exit(1)


def stats_check(target_address, api_key, job, timeout, tls_verify):
    logger.debug(
        '[' + target_address + '] Function called with following parameters:')
    logger.debug('[' + target_address +
                 '] Target Device                    = ' + target_address)
    logger.debug(
        '[' + target_address + '] PANOS API Key                    = ' + api_key)
    logger.debug(
        '[' + target_address + '] PANOS Job ID                     = ' + str(job))
    logger.debug(
        '[' + target_address + '] PANOS API Timeout                = ' + timeout)
    logger.debug('[' + target_address +
                 '] SSL/TLS Certificate Verification = ' + str(tls_verify))
    logger.info('[' + target_address + '] Checking stats-dump job status on: ' +
                target_address + ' (ID: ' + str(job) + ')')

    # Set our status handler
    status = ''

    # Construct our API call
    uri = 'https://' + target_address + \
        '/api/?type=export&category=stats-dump&action=status&job-id=' + job + '&key=' + api_key
    logger.debug('[' + target_address + '] Constructed URI: ' + uri)

    # Output the job id to the command line
    logger.info('[' + target_address + '] Checking commit status for job: ' +
                job + ' on target: ' + target_address)

    # Begin a while loop until the commit is successful
    while status is not 'FIN':
        # Execute the API call against the target device
        response = requests.get(uri, timeout=int(timeout), verify=tls_verify)

        # Check if the API returned a 200 "success" status code
        if response.status_code is 200:
            logger.debug(
                '[' + target_address + '] Status code 200 received, validating response...')

            # Parse the XML response
            status_xml = ET.fromstring(response.content)

            # Map the status and result responses
            status = status_xml.find('./result/job/status').text
            result = status_xml.find('./result/job/result').text

            logger.debug(
                '[' + target_address + '] Response job status: ' + status)
            logger.debug(
                '[' + target_address + '] Response job result: ' + result)

            # Perform validation on response
            if "ACT" in status:
                # Get the progress of the commit
                progress = status_xml.find('./result/job/progress').text
                logger.debug('[' + target_address + ']' + response.text)
                logger.info('[' + target_address + '] Job ID ' +
                            job + ' progress: ' + progress + '%')

                # Update the status handler to "PEND"
                status = "PEND"
            elif "FIN" in status:
                logger.debug('[' + target_address + ']' + response.text)
                logger.info(
                    '[' + target_address + '] Successfully generated statistics dump')

                # Update the status to "FIN", causing the while loop to finish
                status = "FIN"

            elif "PEND" in status:
                logger.debug('[' + target_address + ']' + response.text)
                logger.warning(
                    '[' + target_address + '] Another job is pending, retrying in ' + timeout + ' seconds...')
                status = "PEND"
            else:
                logger.error(
                    '[' + target_address + '] Something went wrong, please consult debug output in the log file')
                logger.error('[' + target_address + ']' + response.text)
                status = "FIN"

            # Sleep the while loop for XYZ seconds
            logger.info('[' + target_address + '] Sleeping for ' +
                        timeout + ' seconds...')
            time.sleep(int(timeout))

        else:
            # Generate an error log
            logger.error('[' + target_address + '] Unable to check commit status on target: ' +
                         target_address + ' (Job: ' + job + ')')

            # Parse XML response
            xml = ET.fromstring(response.content)

            # Output the error message from the API and exit
            logger.error(xml.find('./msg/line').text)
            logger.debug('[' + target_address + ']' + xml)

    # Return true/false to generate_stats()
    if status is "FIN":
        return True
    else:
        return False


def stats_download(target_address, api_key, job, timeout, tls_verify):
    logger.debug(
        '[' + target_address + '] Function called with following parameters:')
    logger.debug('[' + target_address +
                 '] Target Device                    = ' + target_address)
    logger.debug(
        '[' + target_address + '] PANOS API Key                    = ' + api_key)
    logger.debug(
        '[' + target_address + '] PANOS Job ID                     = ' + str(job))
    logger.debug(
        '[' + target_address + '] PANOS API Timeout                = ' + timeout)
    logger.debug('[' + target_address +
                 '] SSL/TLS Certificate Verification = ' + str(tls_verify))
    logger.info('[' + target_address + '] Attempting to download stats-dump file from ' +
                target_address + ' (Job ID: ' + job + ')')

    # Get current time, NATO/ISO 8601 format (YYYY-MM-DD-hh-mm-ss)
    timestr = time.strftime("%Y%m%d-%H%M%S")

    # Set the output filename to reflect [TIME]-stats_dump.tar.gz
    stats_file = target_address + '-' + timestr + '-stats_dump.tar.gz'
    logger.info('[' + target_address + '] File output will be: ' + stats_file)

    # Construct the API call
    uri = 'https://' + target_address + \
        '/api/?type=export&category=stats-dump&action=get&job-id=' + job + '&key=' + api_key
    logger.debug('[' + target_address + '] Constructed URI: ' + uri)
    logger.info('[' + target_address +
                '] Preparing to download statistics dump from target: ' + target_address)

    # Execute
    response = requests.get(
        uri, stream=True, timeout=int(timeout), verify=tls_verify)

    # Write file to disk
    with open(stats_file, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)

    # Validate if the download was successfully written to disk
    if os.path.isfile(stats_file):
        logger.info('[' + target_address +
                    '] Successfully downloaded statistics dump from: ' + target_address)
        return stats_file

    else:
        logger.error('[' + target_address + ']' +
                     stats_file + ' was not found')
        return False


def upload_stats(target_address, stats_dump, config, tls_verify):
    logger.debug(
        '[' + target_address + '] Function called with following parameters:')
    logger.debug(
        '[' + target_address + '] Stats Dump File                  = ' + stats_dump)
    logger.debug(
        '[' + target_address + '] Configuration                    = ' + str(config))
    logger.info('[' + target_address +
                '] Attempting to upload stats-dump file to Palo Alto Networks')

    # Buffer the stats dump file
    file_handler = open(stats_dump, 'rb')

    # SLR API URL
    url = "https://riskreport.paloaltonetworks.com/API/v1/Create"

    # Assign our headers
    headers = {"apikey": config["slr_csp"]}

    # Assign our file to upload
    file = {"files": (stats_dump, file_handler, 'application/gzip')}

    # Assign our data payload
    payload = {"EmailIdList": config['slr_sendto'],
               "RequestedBy": config["slr_requestedby"],
               "PreparedBy": config['slr_preparedby']}

    # Check if additional parameters are defined, if they are add them to the payload dictionary
    # Account Name
    if config['slr_accountname'] is not None:
        payload["AccountName"] = config['slr_accountname']
        logger.info(
            '[' + target_address + '] Setting account name to: ' + payload["AccountName"])
    else:
        logger.warning(
            '[' + target_address + '] No account name specified in config, using SFDC default')

    # Industry
    if config['slr_industry'] is not None:
        payload["Industry"] = config['slr_industry']
        logger.info(
            '[' + target_address + '] Setting industry to: ' + payload["Industry"])
    else:
        logger.warning(
            '[' + target_address + '] No industry specified in config, using SFDC default')

    # Country
    if config['slr_country'] is not None:
        payload["Country"] = config['slr_country']
        logger.info(
            '[' + target_address + '] Setting country to: ' + payload["Country"])
    else:
        logger.warning(
            '[' + target_address + '] No country specified in config, using SFDC default')

    # Region
    # TODO: Bug with SLR API, region causes an error, disabled for now
    # if config['slr_region'] is not None:
    #    payload["GeographicRegion"] = config['slr_region']
    #    logger.info('[' + target_address + '] Setting geographic region to: ' + payload["GeographicRegion"])
    # else:
    #    logger.warning('[' + target_address + '] No geographic region specified in config, using SFDC default')

    # Region
    if config['slr_region'] is not None:
        logger.warning(
            '[' + target_address + '] There is an issue with the Geographic Region option in SFDC, ignoring option...')
    else:
        logger.warning(
            '[' + target_address + '] There is an issue with the Geographic Region option in SFDC, ignoring option...')

    # Deployment Location
    if config['slr_deploymentlocation'] is not None:
        payload["DeploymentLocation"] = config['slr_deploymentlocation']
        logger.info('[' + target_address + '] Setting deployment location to: ' +
                    payload["DeploymentLocation"])
    else:
        logger.warning(
            '[' + target_address + '] No deployment location specified in config, using SFDC default')

    # Language
    if config['slr_language'] is not None:
        payload["Language"] = config['slr_language']
        logger.info(
            '[' + target_address + '] Setting language to: ' + payload["Language"])
    else:
        payload["Language"] = "English"
        logger.warning(
            '[' + target_address + '] No language specified in config, defaulting to ' + payload["Language"])

    # Upload statistics dump to Palo Alto Networks
    logger.info('[' + target_address + '] Uploading...')
    upload_timeout = config['system_uploadtimeout']

    slr_req = requests.post(url, headers=headers, data=payload,
                            files=file, timeout=int(upload_timeout), verify=tls_verify)

    # Check if the API returned a 200 "success" status code
    # TODO: Perform additional validation on API response
    if slr_req.status_code is 200:
        # Successful upload
        logger.debug(slr_req.content)

        # Get the SLR Reference ID from the API response
        json_response = json.loads(slr_req.text)
        slr_id = json_response['Id']

        logger.info('[' + target_address +
                    '] Successfully uploaded statistics dump to Palo Alto Networks')
        logger.info('[' + target_address + '] SLR Reference ID: ' + slr_id)
        logger.info('[' + target_address +
                    '] The SLR report will be sent to: ' + config['slr_sendto'])
        return True
    else:
        # Generate an error log
        logger.error(
            '[' + target_address + '] There was an issue submitting the statistics dump to Palo Alto Networks')
        logger.error('[' + target_address + ']' + slr_req.text)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Palo Alto Networks Automatic SLR Generator")

    # Add command line arguments for configuration and log files
    parser.add_argument("-c", "--config", action="store",
                        dest="config", required=True, help="Define the config file")
    parser.add_argument("-l", "--log", action="store",
                        dest="log", required=True, help="Define the log file")

    # Optional verbosity counter
    parser.add_argument("-v", "--verbose", action="store_true",
                        required=False, help="Enable verbose logging output")

    # Specify output of "--version"
    parser.add_argument("--version", action="version",
                        version="%(prog)s (version {version})".format(version=__version__))

    # Assign command line arguments to handler
    args = parser.parse_args()

    # Configure minimum logging level
    if args.verbose is True:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Define the log format to use for the console and log file
    log_format_console = '%(color)s[%(asctime)s][%(funcName)s:%(lineno)d][%(levelname)s]%(end_color)s %(message)s'
    log_format_file = '[%(asctime)s][%(process)d][%(funcName)s:%(lineno)d][%(levelname)s] %(message)s'

    # Configure the formatters and attach format to console
    formatter_console = logzero.LogFormatter(
        fmt=log_format_console, datefmt='%Y-%m-%d %H:%M:%S')
    formatter_file = logzero.LogFormatter(
        fmt=log_format_file, datefmt='%Y-%m-%d %H:%M:%S')
    logzero.formatter(formatter_console)

    # Configure the console log level
    logzero.loglevel(level=level, update_custom_handlers=False)

    # Configure the logging file
    logzero.logfile(args.log, formatter=formatter_file, maxBytes=1e6, backupCount=3,
                    loglevel=level)

    # Go to main()
    main(args)
