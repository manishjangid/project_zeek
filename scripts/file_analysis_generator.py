#!/usr/bin/env python3

# Need virustotal api installed for python3 by 
# pip3 install virustotal-api
"""file_analysis_generator.py Version 0.1 """

__author__      = "Manish Kumar"
__copyright__   = "Copyright 2020, Project Zeek"

import hashlib
import argparse
import os
import magic
import response
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

def get_virus_total_analysis(filename):
    '''
    I made a virus total account for the api key.
    here's my key: 5e6d601d5b50d952371389fa2b363a86cfc41c9e5a7278bb53f9da03b0521934
    '''
    api_key = "5e6d601d5b50d952371389fa2b363a86cfc41c9e5a7278bb53f9da03b0521934"
    vt = VirusTotalPublicApi(api_key)
    with open(filename,"rb") as f:
        md5 = hashlib.md5(f.read()).hexdigest()
        response = vt.get_file_report(md5)
    print(response.json())

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
    file_content.append(os.path.basename(filename))
    file_content.append(os.stat(filename).st_size)
    if (check_sha256 == True):
        sha_256 = calculate_sha_256_file(filename)
        file_content.append(sha_256)
    if (check_mime == True):
        mime_type = calculate_mime_type(filename)
        file_content.append(mime_type)

    if (len(output_path_file) != 0):

        # Add header if file is a new file
        my_file = Path(output_path_file)
        if not my_file.is_file():
            file_header = ["FileName", "FileSize", "SHA-256", "MimeType", "VirusTotal result",]
            append_to_csv_file(output_path_file, file_header)

        append_to_csv_file(output_path_file, file_content)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File Analysis Generator')
    parser.add_argument('--workspace', metavar='directory_path', required=True,
                        help='the path to object files')
    parser.add_argument('--write_to_csv', metavar='output_directory_path', required=True,
                        help='path to output csv file')
    args = parser.parse_args()

    with os.scandir(args.workspace) as directory:
        for entry in directory:
            if entry.is_file():
                print("File Name: ", entry.name, "Path: ", entry.path)
                do_file_analysis(entry.path,output_path_file = args.write_to_csv)
    
