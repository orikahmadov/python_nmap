import argparse
import subprocess
import socket
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def run_nmap_scan(target):
    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        # Assume target is already an IP address
        ip_address = target

    nmap_command = f'nmap -Pn -sS -sV {ip_address}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def generate_report(target, output_file):
    # Run the Nmap scan
    scan_results = run_nmap_scan(target)

    # Generate the PDF report
    pdf_file = canvas.Canvas(output_file, pagesize=letter)
    pdf_file.drawString(100, 750, f"Nmap Scan Results for {target}")
    pdf_file.drawString(100, 700, scan_results)
    pdf_file.save()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run an Nmap scan and generate a PDF report')
    parser.add_argument('-t', '--target', required=True, help='Target IP address or DNS name')
    parser.add_argument('-o', '--output', required=True, help='Output file for the PDF report')
    args = parser.parse_args()

    generate_report(args.target, args.output)
