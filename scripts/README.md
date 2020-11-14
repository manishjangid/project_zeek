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

```
