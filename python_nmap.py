import argparse
import subprocess
import socket
from fpdf import FPDF

def run_host_discovery(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap -sn {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def run_port_scan(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap -sS -p 1-65535 -T4 -v {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def run_version_detection(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap -sS -sV {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def run_os_detection(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap -sS -O {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def run_traceroute(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap --traceroute {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def run_script_scan(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap -sS -sV -sC {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def generate_report(target, output_file):
    # Run the Nmap scans
    host_discovery_results = run_host_discovery(target)
    port_scan_results = run_port_scan(target)
    version_detection_results = run_version_detection(target)
    os_detection_results = run_os_detection(target)
    traceroute_results = run_traceroute(target)
    script_scan_results = run_script_scan(target)

    # Generate the PDF report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f'Nmap Scan Results for {target}', 0, 1)
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10, f'Host Discovery:\n\n{host_discovery_results}\n\n')
    pdf.multi_cell(0, 10, f'Port Scan:\n\n{port_scan_results}\n\n')
    pdf.multi_cell(0, 10, f'Version Detection:\n\n{version_detection_results}\n\n')
    pdf.multi_cell(0, 10, f'OS Detection:\n\n{os_detection_results}\n\n')
    pdf.multi_cell(0, 10, f'Traceroute:\n\n{traceroute_results}\n\n')
    pdf.multi_cell(0, 10, f'Script Scan:\n\n{script_scan_results}\n\n')
    pdf.output(output_file, 'F')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Target host or IP address')
    parser.add_argument('-o', '--output', help='Output file')
    args = parser.parse_args()

    if args.output:
        generate_report(args.target, args.output)
    else:
        generate_report(args.target, 'nmap_report.pdf')

if __name__ == '__main__':
    main()
