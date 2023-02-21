from reportlab.pdfgen import canvas
import argparse
import os
import subprocess
import datetime

def parse_args():
    parser = argparse.ArgumentParser(description='Nmap scanner script')
    parser.add_argument('-t', '--targets', help='Target IP address(es) or CIDR range(s) (comma-separated)', required=True)
    parser.add_argument('-o', '--output', help='Output directory', default='.')
    parser.add_argument('-f', '--format', help='Output format (txt or pdf)', choices=['txt', 'pdf'], default='txt')
    return parser.parse_args()

def run_nmap_scan(targets):
    nmap_command = f'nmap -Pn -sS -sV {targets}'
    process = subprocess.Popen(nmap_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output.decode()

def generate_report(scan_results, output_dir, output_format):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    current_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    if output_format == 'txt':
        report_file = os.path.join(output_dir, f'nmap_scan_results_{current_time}.txt')
        with open(report_file, 'w') as f:
            f.write(scan_results)
    elif output_format == 'pdf':
        report_file = os.path.join(output_dir, f'nmap_scan_results_{current_time}.pdf')
        pdf = canvas.Canvas(report_file)
        pdf.drawString(100, 100, scan_results)
        pdf.save()
    return report_file

def main():
    args = parse_args()
    targets = args.targets.replace(' ', '').split(',')
    output_dir = args.output
    output_format = args.format

    scan_results = ""
    for target in targets:
        scan_results += run_nmap_scan(target) + '\n'

    report_file = generate_report(scan_results, output_dir, output_format)
    print(f"Report saved to {report_file}")

if __name__ == '__main__':
    main()



