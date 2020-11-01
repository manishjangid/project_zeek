#!/usr/bin/env python

"""file_analysis_generator.py Version 0.1 """

__author__      = "Manish Kumar"
__copyright__   = "Copyright 2020, Project Zeek"

import hashlib
import argparse
import os
from csv import writer

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
    TBD
    '''

def get_virus_total_analysis(filename):
    '''
    TBD
    '''

def do_file_analysis(filename, check_mime=True, check_sha256=True, output_path_file=""):
    '''
    Calculate SHA-256, Mime type, check for VirusTotal analysis with hash file and then 
    add it to csv file
    '''
    file_content = []
    file_content.append(filename)
    if (check_sha256 == True):
        sha_256 = calculate_sha_256_file(filename)
        file_content.append(sha_256)
    if (check_mime == True):
        mime_type = calculate_mime_type(filename)
        file_content.append(mime_type)

    if (len(output_path_file) != 0):
        append_to_csv_file(output_path_file, file_content)

def append_to_csv_file(filename, data):
    '''
    '''
    with open(filename, 'a+', newline='') as write_obj:
        csv_writer = writer(write_obj)
        # Add contents of list as last row in the csv file
        csv_writer.writerow(data)

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
    