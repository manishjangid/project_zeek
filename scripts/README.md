# Python Module 
Used for Submission of the files to VirusTotal and analysing it which will write the results to CSV files

```sh
$ cd scripts

For Help strings

$ python3 file_analysis_generator.py --help

For submissions to Virus Total
$ python3 file_analysis_generator.py --mode submit --workspace test_files/ 

For analysing the files with VirusTotal and then writing the results to csv file
$ python3 file_analysis_generator.py --mode analyse --workspace test_files/ --write_to_csv ./output_file.csv


zeek@zeek:~$ python3 file_analysis_generator.py --mode analyse --workspace ./extract_files/ --write_to_csv ./output_file.csv
File Name:  HTTP-FBhjeo42wHYKTQvaJ1.html Path:  ./extract_files/HTTP-FBhjeo42wHYKTQvaJ1.html
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-Fz275149YdxoDBYdO5.txt Path:  ./extract_files/HTTP-Fz275149YdxoDBYdO5.txt
File Result :  Not Scanned in VirusTotal
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-FrzIIn2Ow8pMryHMkg.html Path:  ./extract_files/HTTP-FrzIIn2Ow8pMryHMkg.html
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-F93UIA4Mazp9iJTFh2.txt Path:  ./extract_files/HTTP-F93UIA4Mazp9iJTFh2.txt
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-FbTttd1WfN11kwnx3d.txt Path:  ./extract_files/HTTP-FbTttd1WfN11kwnx3d.txt
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-FjdlCNVTuSDpmCT34.exe Path:  ./extract_files/HTTP-FjdlCNVTuSDpmCT34.exe
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-F0K3LeogLFo6mTvXf.html Path:  ./extract_files/HTTP-F0K3LeogLFo6mTvXf.html
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

File Name:  HTTP-FPfAyZ2eqQfg5SB6O7.exe Path:  ./extract_files/HTTP-FPfAyZ2eqQfg5SB6O7.exe
File Result :  Benign
 1 seconds remaining for next analysis>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



```
