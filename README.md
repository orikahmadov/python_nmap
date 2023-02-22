# python_nmap
Automated nmap scans with python 


Nmap Scanner
This script is a wrapper around the Nmap tool that performs a variety of scans on a target host or IP address and generates a PDF report of the results.

Scans performed
The script performs the following Nmap scans on the target:

Host discovery (-sn option): This scan is used to determine which hosts are up and running on the target network.

Port scan (-sS option): This scan is used to scan for open TCP ports on the target. The script scans all 65535 TCP ports on the target using a TCP SYN scan.

Version detection (-sV option): This scan is used to identify the software and version numbers of the services running on the open ports detected by the port scan.

OS detection (-O option): This scan is used to identify the operating system running on the target.

Traceroute (--traceroute option): This scan is used to map the path that packets take from the host running Nmap to the target.

Script scan (-sC option): This scan is used to execute a set of default Nmap scripts against the open ports detected by the port scan. These scripts can be used to gather additional information about the target and its services.

Usage
The script can be run from the command line using the following syntax:


Copy code
python nmap_scanner.py target [-o output_file]
where target is the IP address or hostname of the target to be scanned, and output_file (optional) is the name of the PDF file to which the results will be written. If output_file is not specified, the default filename "nmap_report.pdf" will be used.

Example
To scan the target host "example.com" and generate a report to the file "example_report.pdf", run the following command:

Copy code
python nmap_scanner.py example.com -o example_report.pdf
This will perform all of the Nmap scans on the target and write the results to the specified output file.

Dependencies
The script requires the following dependencies to be installed:

argparse: for parsing command line arguments
subprocess: for running Nmap commands
socket: for resolving hostnames to IP addresses
fpdf: for generating the PDF report of the results
These dependencies can be installed using pip:

perl
Copy code
pip install argparse subprocess socket fpdf
Alternatively, you can use the requirements.txt file provided in the repository to install all dependencies at once:

Copy code
pip install -r requirements.txt
License
This script is released under the MIT License
