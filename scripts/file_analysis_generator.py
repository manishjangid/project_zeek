#!/usr/bin/env python3

# Need virustotal api installed for python3 by 
# pip3 install virustotal-api
# pip3 install python-magic
"""file_analysis_generator.py Version 0.2 """

__author__      = "Manish Kumar"
__copyright__   = "Copyright 2020, Project Zeek"

import hashlib
import argparse
import time
import os
import magic
import requests
from csv import writer
from pathlib import Path
from virus_total_apis import PublicApi as VirusTotalPublicApi


def calculate_sha_256_file(filename):
    '''
    Calculate SHA-256 for the file provided as parameter
    '''
    hash = hashlib.sha256()
    with open(filename,"rb") as f:
        # Read in blocks of 4096 bytes and append the hash 
        for byte_block in iter(lambda: f.read(4096),b""):
            hash.update(byte_block)
    return (hash.hexdigest())

def calculate_mime_type(filename):
    '''
    Get mime type for file specified
    '''
    mime = magic.Magic(mime=True)
    return mime.from_file(filename)

def _return_response_and_status_code(response, json_results=True):
    """ Output the requests response content or content as json and status code
    :rtype : dict
    :param response: requests response object
    :param json_results: Should return JSON or raw content
    :return: dict containing the response content and/or the status code with error string.
    """
    if response.status_code == requests.codes.ok:
        return dict(results=response.json() if json_results else response.content, response_code=response.status_code)
    elif response.status_code == 400:
        return dict(
            error='package sent is either malformed or not within the past 24 hours.',
            response_code=response.status_code)
    elif response.status_code == 204:
        return dict(
            error='You exceeded the public API request rate limit (4 requests of any nature per minute)',
            response_code=response.status_code)
    elif response.status_code == 403:
        return dict(
            error='You tried to perform calls to functions for which you require a Private API key.',
            response_code=response.status_code)
    elif response.status_code == 404:
        return dict(error='File not found.', response_code=response.status_code)
    else:
        return dict(response_code=response.status_code)

def send_file_to_virus_total(filename):

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': '5e6d601d5b50d952371389fa2b363a86cfc41c9e5a7278bb53f9da03b0521934'}

    files = {'file': (filename, open(filename, 'rb'))}

    response = requests.post(url, files=files, params=params)
    print(response.json())

def get_virus_total_analysis(sha_256):
    '''
    I made a virus total account for the api key.
    here's my key: 5e6d601d5b50d952371389fa2b363a86cfc41c9e5a7278bb53f9da03b0521934
    '''
    api_key = "5e6d601d5b50d952371389fa2b363a86cfc41c9e5a7278bb53f9da03b0521934"
    vt = VirusTotalPublicApi(api_key)
    response = vt.get_file_report(sha_256)
    params = {'apikey': api_key, 'resource': sha_256}
    try:
        response = requests.get("https://www.virustotal.com/vtapi/v2/" + 'file/report', params=params, timeout=None)
    except requests.RequestException as e:
        return dict(error=str(e))

    return _return_response_and_status_code(response)

def append_to_csv_file(filename, data):
    """[Append to CSV file ]

    Args:
        filename ([string]): [File Name Path]
        data ([list]): [Row Entry for CSV file]
    """

    with open(filename, 'a+', newline='') as write_obj:
        csv_writer = writer(write_obj)
        # Add contents of list as last row in the csv file
        csv_writer.writerow(data)

def do_file_analysis(filename, check_mime=True, check_sha256=True, output_path_file=""):
    '''
    Calculate SHA-256, Mime type, check for VirusTotal analysis with hash file and then 
    add it to csv file
    '''
    
    file_content = []
    sha_256 = ""
    file_content.append(os.path.basename(filename))
    file_content.append(os.stat(filename).st_size)
    if (check_sha256 == True):
        sha_256 = calculate_sha_256_file(filename)
        file_content.append(sha_256)
        
    if (check_mime == True):
        mime_type = calculate_mime_type(filename)
        file_content.append(mime_type)

    if (check_sha256 == True):
        is_malicious_dict = get_virus_total_analysis(sha_256)
        print(is_malicious_dict)
        if ("positives" not in is_malicious_dict["results"]):
            file_content.append("Not Scanned in VirusTotal")
        elif (is_malicious_dict["results"]["positives"] != 0):
            file_content.append("Malicious")
        else:
            file_content.append("Benign") 
   
    if (len(output_path_file) != 0):

        # Add header if file is a new file
        my_file = Path(output_path_file)
        if not my_file.is_file():
            file_header = ["FileName", "FileSize", "SHA-256", "MimeType", "VirusTotal result",]
            append_to_csv_file(output_path_file, file_header)

        append_to_csv_file(output_path_file, file_content)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File Analysis Generator')
    parser.add_argument('--workspace', metavar='directory_path', required=False,
                        help='the path to object files')
    parser.add_argument('--write_to_csv', metavar='output_directory_path', required=False,
                        help='path to output csv file')
    parser.add_argument('--mode', metavar='mode', required=True,
                        help='Scan mode: submit files/retrieve files')
    args = parser.parse_args()

    with os.scandir(args.workspace) as directory:
        for entry in directory:
            if entry.is_file():
                print("File Name: ", entry.name, "Path: ", entry.path)
                if (args.mode == "submit"):
                    # There is a limit of 4 transactions per minute so we will limit it by 20 seconds per request
                    send_file_to_virus_total(entry.path)
                    time.sleep(20)
                elif (args.mode == "analyse"):
                    do_file_analysis(entry.path,output_path_file = args.write_to_csv)
                else:
                    print("Invalid mode : valid is (submit/analyse)")
                    break

