# Learnings

## VirusTotal
VirusTotal provides REST APIs to programmatically retrieve information about the file whether it's malicious/benign. There are 2 version of the API
public and premium. We will be using Public version which provides 500 requests per day with a limit of 4 requests per hour. 
Python provides virustotal-api which is a wrapper for these APIs and can be used to get information about the file by providing the SHA-256 value of the file.

[VirusTotal API](https://developers.virustotal.com/reference#getting-started "VirusTotal API")

## hashlib 
Python library can be used to get SHA-256, MD5 values calculated for the specified file


