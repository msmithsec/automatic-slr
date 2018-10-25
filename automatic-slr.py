#!/usr/bin/python
# Copyright (c) 2018
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

import argparse
import configparser
import json
import logging
import os
import socket
import sys
import time
import xml.etree.ElementTree as ET
from logging.handlers import SysLogHandler
from time import sleep

import requests
import urllib3

# Global Variables
__version__ = '1.0.0'

# Configure argparse
parser = argparse.ArgumentParser(
    description='Palo Alto Networks Automated SLR Generator (Version: ' + __version__ + ')')
parser.add_argument('-c', '--config', help='Define the configuration file', required=True)
parser.add_argument('-l', '--log', help='Define the log file', required=True)
parser.add_argument('-v', '--verbose', help='Enable verbose logging output to the console and log file',
                    action="store_true")

# Map command line arguments
args = parser.parse_args()
api_config = args.config
api_log = args.log
api_verbose = args.verbose

# Create the global logging handler
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
system_fqdn = socket.getfqdn()
log_format = logging.Formatter('[%(asctime)s][%(process)d][%(funcName)s][%(levelname)s] %(message)s',
                               '%Y-%m-%d %H:%M:%S')

# Create the logging handler for writing to a log file
handler_file = logging.FileHandler(api_log)

if api_verbose is True:
    handler_file.setLevel(logging.DEBUG)
else:
    handler_file.setLevel(logging.INFO)

handler_file.setFormatter(log_format)

# Create the logging handler for writing to the console
handler_console = logging.StreamHandler(sys.stdout)

if api_verbose is True:
    handler_console.setLevel(logging.DEBUG)
else:
    handler_console.setLevel(logging.INFO)

handler_console.setFormatter(log_format)

# Add the logging handlers to the logger
log.addHandler(handler_file)
log.addHandler(handler_console)


def main():
    log.info('Palo Alto Networks Automated SLR Generator (Version: ' + __version__ + ')')
    log.info('-----------------------------------------------------------')

    # Parse and map our configuration files
    log.info('Preparing to read configuration file: ' + api_config)
    config = read_configuration(args.config)

    # Enable/Disable Syslog support
    if 'true' in config['syslog_enabled']:
        configure_syslog(config)
    else:
        log.warning('Syslog support is not enabled!')

    # Enable/Disable SSL/TLS verification
    if 'true' in config['system_verify']:
        log.info('SSL/TLS certification verification is enabled')
        tls_verify = True
    else:
        log.warning('SSL/TLS certification verification is disabled!')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        tls_verify = False

    # Connect to the target firewall/panorama and generate the statistics dump
    job = generate_stats(config['target_address'], config['target_key'], config['system_panostimeout'],
                         tls_verify)

    # Download the statistics dump from the target firewall/panorama
    file = download_stats(config['target_address'], config['target_key'], job, config['system_panostimeout'],
                          tls_verify)

    # Upload the statistics dump to the SLR API for generation
    upload = upload_stats(file, config, config['system_uploadtimeout'], tls_verify)

    if upload is True:
        log.info('Finished executing, have a nice day!')
        sys.exit(0)
    else:
        log.error('Something went wrong, please consult the log file for more information.')
        sys.exit(1)


def read_configuration(configuration_file):
    log.debug('Function called with parameter: configuration_file = ' + configuration_file)

    # Create configuration parser handler
    config = configparser.ConfigParser(allow_no_value=True)

    # Check if the configuration file exists, if it does, read the configuration file
    file = os.path.isfile(configuration_file)

    if file is True:
        log.info('Configuration file exists check passed, reading configuration file...')
        config.read(configuration_file)
        log.info('Configuration file read, parsing configuration values...')
    else:
        log.error('Configuration file defined does not exist, exiting...')
        sys.exit(1)

    # Setup our Python dictionary to store configuration values
    conf = {}

    # Map configuration values for the target device
    conf['target_address'] = config.get('target', 'address')
    conf['target_key'] = config.get('target', 'key')
    conf['target_mode'] = config.get('target', 'mode')

    # Map configuration values for the SLR attributes
    conf['slr_preparedby'] = config.get('SLR', 'preparedby')
    conf['slr_requestedby'] = config.get('SLR', 'requestedby')
    conf['slr_sendto'] = config.get('SLR', 'sendto')
    conf['slr_csp'] = config.get('SLR', 'cspkey')
    conf['slr_accountname'] = config.get('SLR', 'accountname')
    conf['slr_industry'] = config.get('SLR', 'industry')
    conf['slr_country'] = config.get('SLR', 'country')
    conf['slr_region'] = config.get('SLR', 'geographicregion')
    conf['slr_deploymentlocation'] = config.get('SLR', 'deploymentlocation')
    conf['slr_language'] = config.get('SLR', 'language')

    # Map configuration values for general system behaviour
    conf['system_version'] = __version__
    conf['system_panostimeout'] = config.get('system', 'panos_timeout')
    conf['system_uploadtimeout'] = config.get('system', 'upload_timeout')
    conf['system_verify'] = config.get('system', 'verify')

    # Map configuration values for syslog support
    conf['syslog_enabled'] = config.get('syslog', 'enabled')
    conf['syslog_address'] = config.get('syslog', 'address')
    conf['syslog_port'] = config.get('syslog', 'port')
    conf['syslog_protocol'] = config.get('syslog', 'protocol')
    conf['syslog_facility'] = config.get('syslog', 'facility')

    # Output mapping results to the command line
    log.info(' [Target] address         = ' + conf['target_address'])
    log.debug('[Target] key             = ' + conf['target_key'])
    log.info(' [Target] mode            = ' + conf['target_mode'])
    log.info(' [SLR] preparedby         = ' + conf['slr_preparedby'])
    log.info(' [SLR] requestedby        = ' + conf['slr_requestedby'])
    log.info(' [SLR] sendto             = ' + conf['slr_sendto'])
    log.debug('[SLR] cspkey             = ' + conf['slr_csp'])
    log.info(' [SLR] Account            = ' + conf['slr_accountname'])
    log.info(' [SLR] Industry           = ' + conf['slr_industry'])
    log.info(' [SLR] Country            = ' + conf['slr_country'])
    log.info(' [SLR] GeographicRegion   = ' + conf['slr_region'])
    log.info(' [SLR] DeploymentLocation = ' + conf['slr_deploymentlocation'])
    log.info(' [SLR] Language           = ' + conf['slr_language'])
    log.info(' [System] version         = ' + conf['system_version'])
    log.info(' [System] panos timeout   = ' + conf['system_panostimeout'] + ' seconds')
    log.info(' [System] upload timeout  = ' + conf['system_uploadtimeout'] + ' seconds')
    log.info(' [System] ssl/tls verify  = ' + conf['system_verify'])
    log.info(' [Syslog] enabled         = ' + conf['syslog_enabled'])
    log.info(' [Syslog] address         = ' + conf['syslog_address'])
    log.info(' [Syslog] port            = ' + conf['syslog_port'])
    log.info(' [Syslog] protocol        = ' + conf['syslog_protocol'])
    log.info(' [Syslog] facility        = ' + conf['syslog_facility'])

    # Return configuration dictionary to main()
    return conf


def generate_stats(target, key, timeout, verify):
    log.debug('Function called with parameters:')
    log.debug('target = ' + target)
    log.debug('key = ' + key)
    log.debug('timeout = ' + timeout + ' seconds')
    log.debug('verify = ' + str(verify))

    # Construct the query URI
    url = 'https://' + target + '/api/?type=export&category=stats-dump&key=' + key
    log.debug('Constructed URL: ' + url)

    log.info('Initiating statistics dump generation on target device: ' + target)
    log.info('Executing...')

    # Run the API request against the target
    response = requests.get(url, timeout=int(timeout), verify=verify)
    log.debug(response.text)

    log.debug(response.status_code)

    # Check if the API returned a 200 "success" status code
    if response.status_code is 200:
        log.info('Status code 200 received, validating response...')

        # Parse XML response
        xml = ET.fromstring(response.content)

        # Determine is an error was encountered
        if 'error' in xml.attrib['status']:
            log.debug('XML Response Status: ' + xml.attrib['status'])
            log.debug('XML Response Debug: ' + response.text)
            log.error(xml.find('./msg/line').text)
            log.debug(xml)
            sys.exit(1)
        else:
            # No error detected in XML response, proceed...
            log.debug('XML Response Status: ' + xml.attrib['status'])

            job = xml.find('./result/job').text
            log.info('Received Job ID: ' + job)

            # Wait for the statistics dump generation job to finish
            status = check_status(target, key, job, timeout, verify)

            if status is True:
                log.info('Statistics dump finished generating')
                return job
            else:
                log.error('Statistics dump failed to generate, please consult the log files in debug mode')
                sys.exit(1)
    else:
        # Generate an error log
        log.error('Unable to initiate statistics dump generation on target: ' + target)

        # Parse XML response
        xml = ET.fromstring(response.content)

        # Output the error message from the API and exit
        log.error(xml.find('./msg/line').text)
        log.debug(xml)
        sys.exit(1)


def check_status(target, key, job, timeout, verify):
    log.debug('Function called with parameters:')
    log.debug('target = ' + target)
    log.debug('key = ' + key)
    log.debug('job = ' + job)
    log.debug('timeout = ' + timeout + ' seconds')
    log.debug('verify = ' + str(verify))

    # Set our status handler
    status = ''

    # Construct our API call
    url = 'https://' + target + '/api/?type=export&category=stats-dump&action=status&job-id=' + job + '&key=' + key
    log.debug('Constructed URL: ' + url)

    # Output the job id to the command line
    log.info('Checking commit status for job: ' + job + ' on target: ' + target)

    # Begin a while loop until the commit is successful
    while status is not 'FIN':
        # Execute the API call against the target device
        response = requests.get(url, timeout=int(timeout), verify=verify)

        # Check if the API returned a 200 "success" status code
        if response.status_code is 200:
            log.debug('Status code 200 received, validating response...')

            # Parse the XML response
            status_xml = ET.fromstring(response.content)

            # Map the status and result responses
            status = status_xml.find('./result/job/status').text
            result = status_xml.find('./result/job/result').text

            log.debug('Response job status: ' + status)
            log.debug('Response job result: ' + result)

            # Perform validation on response
            if "ACT" in status:
                # Get the progress of the commit
                progress = status_xml.find('./result/job/progress').text
                log.debug(response.text)
                log.info('Job ID ' + job + ' progress: ' + progress + '%')

                # Update the status handler to "PEND"
                status = "PEND"
            elif "FIN" in status:
                log.debug(response.text)
                log.info('Successfully generated statistics dump')

                # Update the status to "FIN", causing the while loop to finish
                status = "FIN"

            elif "PEND" in status:
                log.debug(response.text)
                log.warning('Another job is pending, retrying in ' + timeout + ' seconds...')
                status = "PEND"
            else:
                log.error('Something went wrong, please consult debug output in the log file')
                log.error(response.text)
                sys.exit(1)

            # Sleep the while loop for XYZ seconds
            log.info('Sleeping for ' + timeout + ' seconds...')
            sleep(int(timeout))

        else:
            # Generate an error log
            log.error('Unable to check commit status on target: ' + target + ' (Job: ' + job + ')')

            # Parse XML response
            xml = ET.fromstring(response.content)

            # Output the error message from the API and exit
            log.error(xml.find('./msg/line').text)
            log.debug(xml)
            sys.exit(1)

    # Return true/false to generate_stats()
    if status is "FIN":
        return True
    else:
        return False


def download_stats(target, key, job, timeout, verify):
    log.debug('Function called with parameters:')
    log.debug('target = ' + target)
    log.debug('key = ' + key)
    log.debug('job = ' + job)
    log.debug('timeout = ' + timeout + ' seconds')
    log.debug('verify = ' + str(verify))

    # Get serial number of target device
    serial = get_serial(target, key, timeout, verify)

    # Get current time, NATO/ISO 8601 format
    timestr = time.strftime("%Y%m%d-%H%M%S")

    # Set the output filename to reflect [TIME]-stats_dump.tar.gz
    stats_file = serial + '-' + timestr + '-stats_dump.tar.gz'
    log.info('Output filename: ' + stats_file)

    # Construct the API call
    url = 'https://' + target + '/api/?type=export&category=stats-dump&action=get&job-id=' + job + '&key=' + key
    log.debug('Constructed URL: ' + url)
    log.info('Preparing to download statistics dump from target: ' + target)

    # Execute
    response = requests.get(url, stream=True, timeout=int(timeout), verify=verify)

    # Write file to disk
    with open(stats_file, 'wb') as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)

    # Validate if the download was successfully written to disk
    if os.path.isfile(stats_file):
        log.info('Successfully downloaded statistics dump from: ' + target)

        return stats_file

    else:
        log.error(stats_file + ' was not found')
        sys.exit(1)


def upload_stats(stats_dump, config, timeout, verify):
    log.debug('Function called with parameters:')
    log.debug('file = ' + stats_dump)
    log.debug('timeout = ' + timeout + ' seconds')
    log.debug('verify = ' + str(verify))

    log.info('Preparing to upload statistics dump to Palo Alto Networks')

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
        log.info('Setting account name to: ' + payload["AccountName"])
    else:
        log.warning('No account name specified in config, using SFDC default')

    # Industry
    if config['slr_industry'] is not None:
        payload["Industry"] = config['slr_industry']
        log.info('Setting industry to: ' + payload["Industry"])
    else:
        log.warning('No industry specified in config, using SFDC default')

    # Country
    if config['slr_country'] is not None:
        payload["Country"] = config['slr_country']
        log.info('Setting country to: ' + payload["Country"])
    else:
        log.warning('No country specified in config, using SFDC default')

    # Region
    # TODO: Bug with SLR API, region causes an error, disabled for now
    # if config['slr_region'] is not None:
    #    payload["GeographicRegion"] = config['slr_region']
    #    log.info('Setting geographic region to: ' + payload["GeographicRegion"])
    # else:
    #    log.warning('No geographic region specified in config, using SFDC default')

    # Region
    if config['slr_region'] is not None:
        log.warning('There is an issue with the Geographic Region option in SFDC, ignoring option...')
    else:
        log.warning('There is an issue with the Geographic Region option in SFDC, ignoring option...')

    # Deployment Location
    if config['slr_deploymentlocation'] is not None:
        payload["DeploymentLocation"] = config['slr_deploymentlocation']
        log.info('Setting deployment location to: ' + payload["DeploymentLocation"])
    else:
        log.warning('No deployment location specified in config, using SFDC default')

    # Language
    if config['slr_language'] is not None:
        payload["Language"] = config['slr_language']
        log.info('Setting language to: ' + payload["Language"])
    else:
        payload["Language"] = "English"
        log.warning('No language specified in config, defaulting to ' + payload["Language"])

    # Upload statistics dump to Palo Alto Networks
    log.info('Uploading...')
    slr_req = requests.post(url, headers=headers, data=payload, files=file, timeout=int(timeout), verify=verify)

    # Check if the API returned a 200 "success" status code
    # TODO: Perform additional validation on API response
    if slr_req.status_code is 200:
        # Successful upload
        log.debug(slr_req.content)

        # Get the SLR Reference ID from the API response
        json_response = json.loads(slr_req.text)
        slr_id = json_response['Id']

        log.info('Successfully uploaded statistics dump to Palo Alto Networks')
        log.info('SLR Reference ID: ' + slr_id)
        log.info('The SLR report will be sent to: ' + config['slr_sendto'])
        return True
    else:
        # Generate an error log
        log.error('There was an issue submitting the statistics dump to Palo Alto Networks')
        log.error(slr_req.text)
        sys.exit(1)


def get_serial(target, key, timeout, verify):
    log.debug('Function called with parameters:')
    log.debug('target = ' + target)
    log.debug('key = ' + key)
    log.debug('timeout = ' + timeout + ' seconds')
    log.debug('verify = ' + str(verify))

    # Retrieve the serial number of the target device
    log.info('Attempting to retrieve the serial number from target: ' + target)
    url = 'https://' + target + '/api/?type=version&key=' + key
    log.debug('Constructed URL: ' + url)

    # Run the API request against the target
    response = requests.get(url, timeout=int(timeout), verify=verify)
    log.debug(response.text)

    # Check if the API returned a 200 "success" status code
    if response.status_code is 200:
        log.info('Status code 200 received, validating response...')

        # Parse XML response
        xml = ET.fromstring(response.content)

        # Determine is an error was encountered
        if 'error' in xml.attrib['status']:
            log.debug('XML Response Status: ' + xml.attrib['status'])
            log.debug('XML Response Debug: ' + response.text)
            log.error(xml.find('./msg').text)
            log.debug(xml)
            sys.exit(1)
        else:
            # No error detected in XML response, proceed...
            log.debug('XML Response Status: ' + xml.attrib['status'])

            serial = xml.find('./result/serial').text
            log.info('Retrieved serial number: ' + serial)

            return serial
    else:
        # Generate an error log
        log.error('Unable to initiate statistics dump generation on target: ' + target)

        # Parse XML response
        xml = ET.fromstring(response.content)

        # Output the error message from the API and exit
        log.error(xml.find('./msg/line').text)
        log.debug(xml)
        sys.exit(1)


def configure_syslog(config):
    log.info('Syslog support enabled, configuring...')

    if 'udp' in config['syslog_protocol']:
        sock_type = socket.SOCK_DGRAM
    elif 'tcp' in config['syslog_protocol']:
        sock_type = socket.SOCK_STREAM
    else:
        log.error('Unknown protocol type for syslog, valid types are: udp, tcp')
        sys.exit(1)

    syslog_address = (config['syslog_address'], int(config['syslog_port']))
    handler_syslog = SysLogHandler(address=syslog_address, facility=config['syslog_facility'], socktype=sock_type)

    syslog_format = logging.Formatter(
        'hostname=' + system_fqdn + ', recvtime=%(asctime)s, proc=%(process)d, target=' + config[
            'target_address'] + ', function=%(funcName)s, severity=%(levelname)s, message=%(message)s',
        '%Y-%m-%d-%H:%M:%S')

    handler_syslog.setFormatter(syslog_format)

    if api_verbose is True:
        handler_syslog.setLevel(logging.DEBUG)
    else:
        handler_syslog.setLevel(logging.INFO)

    # Add syslog configuration to the logging handler
    log.addHandler(handler_syslog)
    log.debug(
        'Syslog configured to forward to: ' + config['syslog_address'] + ':' + config['syslog_port'] + '/' +
        config['syslog_protocol'])

    pid = str(os.getpid())
    log.info('Syslog support enabled for process: ' + pid + ' for target: ' + config['target_address'])

    return True


if __name__ == '__main__':
    main()
