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

    print("Running host discovery...")
    nmap_command = f'nmap -sn {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print("Host discovery complete.")
    return output.decode()


def run_port_scan(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    print("Running port scan...")
    nmap_command = f'nmap -sS -p 1-65535 -T4 -v {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print("Port scan complete.")
    return output.decode()


def run_version_detection(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    print("Running version detection...")
    nmap_command = f'nmap -sS -sV {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print("Version detection complete.")
    return output.decode()


def run_os_detection(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    print("Running OS detection...")
    nmap_command = f'nmap -sS -O {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print("OS detection complete.")
    return output.decode()


def run_traceroute(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    print("Running traceroute...")
    nmap_command = f'nmap --traceroute {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print("Traceroute complete.")
    return output.decode()


def run_script_scan(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    print("Running script scan...")
    nmap_command = f'nmap -sS -sV -sC {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    print("Script scan complete.")
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
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Nmap Scan Report", ln=1, align="C")
    pdf.cell(200, 10, txt=f"Target: {target}", ln=2, align="C")
    pdf.cell(200, 10, txt="Host Discovery Results", ln=3, align="C")
    pdf.multi_cell(0, 5, txt=host_discovery_results)
    pdf.cell(200, 10, txt="Port Scan Results", ln=4, align="C")
    pdf.multi_cell(0, 5, txt=port_scan_results)
    pdf.cell(200, 10, txt="Version Detection Results", ln=5, align="C")
    pdf.multi_cell(0, 5, txt=version_detection_results)
    pdf.cell(200, 10, txt="OS Detection Results", ln=6, align="C")
    pdf.multi_cell(0, 5, txt=os_detection_results)
    pdf.cell(200, 10, txt="Traceroute Results", ln=7, align="C")
    pdf.multi_cell(0, 5, txt=traceroute_results)
    pdf.cell(200, 10, txt="Script Scan Results", ln=8, align="C")
    pdf.multi_cell(0, 5, txt=script_scan_results)
    pdf.output(output_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-o", "--output", help="Output file name")
    args = parser.parse_args()

    if args.target and args.output:
        generate_report(args.target, args.output)
    else:
        print("Please specify a target and an output file name.")
        print("Use -h or --help for more information.")

if __name__ == "__main__":
    main()
    
