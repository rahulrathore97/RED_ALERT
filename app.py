from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS  # Added CORS support
import threading
import time
import json
import os
import datetime
import tempfile
import sys
import socket
import nmap
import requests
from concurrent.futures import ThreadPoolExecutor
import html

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)  # Enable CORS for all routes

# Store active scans
active_scans = {}
scan_results = {}

class VulnerabilityScanner:
    def __init__(self, target, ports=None, threads=10, timeout=2, scan_id=None):
        self.target = target
        self.ports = ports or "1-1000"  # Default scan first 1000 ports if not specified
        self.threads = threads
        self.timeout = timeout
        self.nm = nmap.PortScanner()
        self.open_ports = []
        self.service_info = {}
        self.vulnerabilities = {}
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_id = scan_id
        self.abort_flag = False
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        self.progress_callback = callback
        
    def send_progress(self, event, data):
        if self.progress_callback:
            self.progress_callback(event, data)
    
    def resolve_host(self):
        """Resolve hostname to IP address"""
        try:
            self.send_progress('scan_init', {'message': f'Resolving hostname {self.target}...'})
            ip = socket.gethostbyname(self.target)
            self.send_progress('scan_init', {'message': f'Hostname resolved to {ip}'})
            return ip
        except socket.gaierror:
            self.send_progress('scan_error', {'message': f'Could not resolve hostname {self.target}'})
            return self.target
    
    def is_port_open(self, port):
        """Check if a port is open using socket"""
        if self.abort_flag:
            return False
            
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        result = s.connect_ex((self.target, port))
        s.close()
        return result == 0
    
    def quick_scan(self):
        """Perform a quick scan to find open ports"""
        self.send_progress('port_scan_start', {'message': f'Starting quick port scan on {self.target}...'})
        
        # Parse port range
        if "-" in self.ports:
            start_port, end_port = map(int, self.ports.split("-"))
            port_list = range(start_port, end_port + 1)
        else:
            port_list = [int(p) for p in self.ports.split(",")]
        
        total_ports = len(port_list)
        scanned_ports = 0
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create a list to store results and ports
            results = []
            for port in port_list:
                if self.abort_flag:
                    break
                future = executor.submit(self.is_port_open, port)
                results.append((port, future))
                
                # Update progress periodically
                scanned_ports += 1
                if scanned_ports % max(1, total_ports // 20) == 0 or scanned_ports == total_ports:
                    progress = scanned_ports / total_ports
                    self.send_progress('port_scan_progress', {
                        'message': f'Scanning ports ({scanned_ports}/{total_ports})...',
                        'progress': progress
                    })
        
        # Process results
        for port, future in results:
            if self.abort_flag:
                break
            try:
                is_open = future.result()
                if is_open:
                    self.open_ports.append(port)
            except Exception:
                pass
        
        if self.open_ports:
            self.send_progress('port_scan_complete', {
                'message': f'Found {len(self.open_ports)} open ports',
                'open_ports': self.open_ports
            })
        else:
            self.send_progress('port_scan_complete', {
                'message': 'No open ports found',
                'open_ports': []
            })
    
    def detailed_scan(self):
        """Perform detailed scan on open ports to get service information"""
        if not self.open_ports or self.abort_flag:
            return
        
        self.send_progress('service_scan_start', {'message': 'Starting detailed service scan on open ports...'})
        
        # Convert list of ports to nmap format
        ports_str = ",".join(map(str, self.open_ports))
        
        try:
            # Run nmap scan with service detection
            self.send_progress('service_scan_progress', {
                'message': 'Running Nmap service detection...',
                'progress': 0
            })
            
            # Split into smaller chunks if there are many ports
            port_chunks = [self.open_ports[i:i + 10] for i in range(0, len(self.open_ports), 10)]
            total_chunks = len(port_chunks)
            
            for i, chunk in enumerate(port_chunks):
                if self.abort_flag:
                    break
                    
                chunk_str = ",".join(map(str, chunk))
                self.nm.scan(self.target, ports=chunk_str, arguments="-sV")
                
                # Process results for this chunk
                for port in chunk:
                    port_str = str(port)
                    if self.target in self.nm.all_hosts() and 'tcp' in self.nm[self.target] and int(port_str) in self.nm[self.target]['tcp']:
                        service_info = self.nm[self.target]['tcp'][int(port_str)]
                        self.service_info[port_str] = {
                            'name': service_info['name'],
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        }
                
                # Update progress
                progress = (i + 1) / total_chunks
                self.send_progress('service_scan_progress', {
                    'message': f'Identifying services ({i + 1}/{total_chunks})...',
                    'progress': progress
                })
            
            self.send_progress('service_scan_complete', {'message': 'Service detection completed'})
            
        except Exception as e:
            self.send_progress('scan_error', {'message': f'Error during detailed scan: {str(e)}'})
    
    def check_vulnerabilities(self):
        """Check for vulnerabilities in detected services"""
        if not self.service_info or self.abort_flag:
            return
        
        self.send_progress('vuln_scan_start', {'message': 'Checking for vulnerabilities...'})
        
        total_services = len(self.service_info)
        processed_services = 0
        
        for port, service in self.service_info.items():
            if self.abort_flag:
                break
                
            product = service['product']
            version = service['version']
            
            if not product:
                processed_services += 1
                continue
                
            # Query the NVD API for vulnerabilities
            self.vulnerabilities[port] = self.query_nvd(product, version)
            
            # Update progress
            processed_services += 1
            progress = processed_services / total_services
            self.send_progress('vuln_scan_progress', {
                'message': f'Checking vulnerabilities ({processed_services}/{total_services})...',
                'progress': progress
            })
        
        self.send_progress('vuln_scan_complete', {'message': 'Vulnerability check completed'})
    
    def query_nvd(self, product, version):
        """Query the NVD database for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Format the search query
            search_term = f"{product}"
            if version:
                search_term += f" {version}"
                
            # Use the NVD API to search for vulnerabilities
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_term}&resultsPerPage=10"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                
                # Process the results
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve_item = vuln['cve']
                        cve_id = cve_item['id']
                        description = cve_item['descriptions'][0]['value'] if cve_item['descriptions'] else "No description available"
                        
                        # Get CVSS score if available
                        cvss_score = "N/A"
                        severity = "N/A"
                        
                        if 'metrics' in cve_item:
                            metrics = cve_item['metrics']
                            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 'N/A')
                                severity = cvss_data.get('baseSeverity', 'N/A')
                            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data.get('baseScore', 'N/A')
                                severity = 'N/A'
                        
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'severity': severity
                        })
        except Exception as e:
            self.send_progress('scan_error', {'message': f'Error querying NVD: {str(e)}'})
        
        return vulnerabilities
    
    def run_scan(self):
        """Run the full vulnerability scan"""
        try:
            self.scan_start_time = datetime.datetime.now()
            
            # Resolve hostname to IP if needed
            if not self.is_ip_address(self.target):
                self.target = self.resolve_host()
            
            if self.abort_flag:
                return
                
            # Run quick scan to find open ports
            self.quick_scan()
            
            if self.abort_flag:
                return
                
            # If open ports found, run detailed scan
            if self.open_ports:
                self.detailed_scan()
                
                if self.abort_flag:
                    return
                    
                self.check_vulnerabilities()
            
            if self.abort_flag:
                return
                
            self.scan_end_time = datetime.datetime.now()
            
            # Generate report
            self.send_progress('report_generation', {'message': 'Generating report...'})
            
            # Create results object
            results = {
                'scan_info': {
                    'target': self.target,
                    'start_time': self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    'end_time': self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S"),
                    'duration': (self.scan_end_time - self.scan_start_time).total_seconds(),
                    'ports_scanned': self.ports,
                    'open_ports_count': len(self.open_ports)
                },
                'open_ports': self.open_ports,
                'services': self.service_info,
                'vulnerabilities': self.vulnerabilities,
                'format': 'html'  # Default format
            }
            
            # Store results
            if self.scan_id:
                scan_results[self.scan_id] = results
            
            # Send completion event
            self.send_progress('scan_complete', {
                'message': 'Scan completed successfully',
                'results': results
            })
            
        except Exception as e:
            self.send_progress('scan_error', {'message': f'Scan error: {str(e)}'})
    
    def is_ip_address(self, address):
        """Check if the given address is an IP address"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def abort(self):
        """Abort the scan"""
        self.abort_flag = True

@app.route('/')
def index():
    return app.send_static_file('index.html')

# Improved event stream handling
@app.route('/api/scan')
def start_scan():
    scan_id = request.args.get('scan_id')
    target = request.args.get('target')
    ports = request.args.get('ports', '1-1000')
    threads = int(request.args.get('threads', 10))
    timeout = float(request.args.get('timeout', 1.0))
    format_type = request.args.get('format', 'html')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Create a queue for events
    event_queue = []
    queue_lock = threading.Lock()
    scan_complete = threading.Event()
    
    def progress_callback(event, data):
        with queue_lock:
            event_queue.append((event, data))
    
    scanner = VulnerabilityScanner(
        target=target,
        ports=ports,
        threads=threads,
        timeout=timeout,
        scan_id=scan_id
    )
    scanner.set_progress_callback(progress_callback)
    
    # Store scanner in active scans
    if scan_id:
        active_scans[scan_id] = scanner
    
    # Run scan in a separate thread
    def run_scan_thread():
        try:
            scanner.run_scan()
        finally:
            scan_complete.set()
    
    scan_thread = threading.Thread(target=run_scan_thread)
    scan_thread.daemon = True
    scan_thread.start()
    
    def generate():
        # Send initial event
        yield f"event: scan_init\ndata: {json.dumps({'message': 'Initializing scan...'})}\n\n"
        
        while not scan_complete.is_set() or event_queue:
            # Check if there are events in the queue
            with queue_lock:
                if event_queue:
                    event, data = event_queue.pop(0)
                    yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
                    continue
            
            # No events, wait a bit
            time.sleep(0.1)
            
            # Send a keep-alive comment to prevent connection timeout
            yield ": keep-alive\n\n"
        
        # Clean up
        if scan_id in active_scans:
            del active_scans[scan_id]
    
    return Response(generate(), mimetype="text/event-stream")

# Fix the report download issue by improving the report endpoint
@app.route('/api/report')
def get_report():
    scan_id = request.args.get('scan_id')
    format_type = request.args.get('format', 'html')
    
    if not scan_id or scan_id not in scan_results:
        return jsonify({'error': 'Invalid scan ID or results not found'}), 400
    
    results = scan_results[scan_id]
    
    # Generate report file
    if format_type == 'json':
        # JSON report
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        with open(temp_file.name, 'w') as f:
            json.dump(results, f, indent=4)
        
        # Return file directly without using after_request
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"vulnerability_scan_{results['scan_info']['target']}_{datetime.datetime.now().strftime('%Y-%m-%d')}.json",
            mimetype='application/json'
        )
        
        # Set cleanup callback
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(temp_file.name)
            except:
                pass
                
        return response
    
    elif format_type == 'txt':
        # Text report
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        with open(temp_file.name, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Scan information
            f.write("SCAN INFORMATION:\n")
            f.write(f"Target: {results['scan_info']['target']}\n")
            f.write(f"Start Time: {results['scan_info']['start_time']}\n")
            f.write(f"End Time: {results['scan_info']['end_time']}\n")
            f.write(f"Duration: {results['scan_info']['duration']:.2f} seconds\n")
            f.write(f"Ports Scanned: {results['scan_info']['ports_scanned']}\n")
            f.write(f"Open Ports Found: {len(results['open_ports'])}\n\n")
            
            # Open ports and services
            f.write("OPEN PORTS AND SERVICES:\n")
            if results['open_ports']:
                for port in results['open_ports']:
                    port_str = str(port)
                    if port_str in results['services']:
                        service = results['services'][port_str]
                        f.write(f"Port {port}: {service['name']} - {service['product']} {service['version']} {service['extrainfo']}\n")
                    else:
                        f.write(f"Port {port}: Unknown\n")
            else:
                f.write("No open ports found.\n")
            
            f.write("\n")
            
            # Vulnerabilities
            f.write("VULNERABILITIES:\n")
            vuln_found = False
            
            for port in results['open_ports']:
                port_str = str(port)
                if port_str in results['vulnerabilities'] and results['vulnerabilities'][port_str]:
                    vuln_found = True
                    service = results['services'].get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                    f.write(f"\nPort {port} - {service['name']} - {service['product']} {service['version']}\n")
                    
                    for vuln in results['vulnerabilities'][port_str]:
                        f.write(f"  CVE ID: {vuln['cve_id']}\n")
                        f.write(f"  CVSS Score: {vuln['cvss_score']}\n")
                        f.write(f"  Severity: {vuln['severity']}\n")
                        f.write(f"  Description: {vuln['description']}\n\n")
            
            if not vuln_found:
                f.write("No vulnerabilities found for any service.\n")
        
        # Return file directly without using after_request
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"vulnerability_scan_{results['scan_info']['target']}_{datetime.datetime.now().strftime('%Y-%m-%d')}.txt",
            mimetype='text/plain'
        )
        
        # Set cleanup callback
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(temp_file.name)
            except:
                pass
                
        return response
    
    else:  # HTML report
        # HTML report
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.html')
        
        scan_duration = results['scan_info']['duration']
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {results['scan_info']['target']}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .severity-high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f39c12;
            font-weight: bold;
        }}
        .severity-low {{
            color: #27ae60;
            font-weight: bold;
        }}
        .cve-id {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .port-header {{
            background-color: #34495e;
            color: white;
            padding: 10px;
            margin-top: 20px;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 0.8em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Scan Report</h1>
        
        <div class="section">
            <h2>Scan Information</h2>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Target</td>
                    <td>{html.escape(results['scan_info']['target'])}</td>
                </tr>
                <tr>
                    <td>Scan Start Time</td>
                    <td>{results['scan_info']['start_time']}</td>
                </tr>
                <tr>
                    <td>Scan End Time</td>
                    <td>{results['scan_info']['end_time']}</td>
                </tr>
                <tr>
                    <td>Duration</td>
                    <td>{scan_duration:.2f} seconds</td>
                </tr>
                <tr>
                    <td>Ports Scanned</td>
                    <td>{html.escape(results['scan_info']['ports_scanned'])}</td>
                </tr>
                <tr>
                    <td>Open Ports Found</td>
                    <td>{len(results['open_ports'])}</td>
                </tr>
            </table>
        </div>
"""
        
        if not results['open_ports']:
            html_content += """
        <div class="section">
            <h2>Open Ports and Services</h2>
            <p>No open ports found.</p>
        </div>
"""
        else:
            html_content += """
        <div class="section">
            <h2>Open Ports and Services</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>Extra Info</th>
                </tr>
"""
            
            for port in results['open_ports']:
                port_str = str(port)
                if port_str in results['services']:
                    service = results['services'][port_str]
                    html_content += f"""
                <tr>
                    <td>{port}</td>
                    <td>{html.escape(service['name'])}</td>
                    <td>{html.escape(service['product'])}</td>
                    <td>{html.escape(service['version'])}</td>
                    <td>{html.escape(service['extrainfo'])}</td>
                </tr>
"""
                else:
                    html_content += f"""
                <tr>
                    <td>{port}</td>
                    <td>Unknown</td>
                    <td></td>
                    <td></td>
                    <td></td>
                </tr>
"""
            
            html_content += """
            </table>
        </div>
"""
            
            # Vulnerabilities section
            html_content += """
        <div class="section">
            <h2>Vulnerabilities</h2>
"""
            
            vuln_found = False
            for port in results['open_ports']:
                port_str = str(port)
                if port_str in results['vulnerabilities'] and results['vulnerabilities'][port_str]:
                    vuln_found = True
                    service = results['services'].get(port_str, {'name': 'Unknown', 'product': '', 'version': ''})
                    
                    html_content += f"""
            <div class="port-header">
                <h3>Port {port} - {html.escape(service['name'])} - {html.escape(service['product'])} {html.escape(service['version'])}</h3>
            </div>
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>CVSS Score</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
"""
                    
                    for vuln in results['vulnerabilities'][port_str]:
                        severity_class = "severity-low"
                        if vuln['severity'] == 'HIGH':
                            severity_class = "severity-high"
                        elif vuln['severity'] == 'MEDIUM':
                            severity_class = "severity-medium"
                        
                        html_content += f"""
                <tr>
                    <td class="cve-id">{html.escape(vuln['cve_id'])}</td>
                    <td class="{severity_class}">{html.escape(str(vuln['cvss_score']))}</td>
                    <td class="{severity_class}">{html.escape(vuln['severity'])}</td>
                    <td>{html.escape(vuln['description'])}</td>
                </tr>
"""
                    
                    html_content += """
            </table>
"""
            
            if not vuln_found:
                html_content += """
            <p>No vulnerabilities found for any service.</p>
"""
            
            html_content += """
        </div>
"""
        
        # Footer
        html_content += f"""
        <div class="footer">
            <p>Report generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} by RED ALERT Vulnerability Scanner</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(temp_file.name, 'w') as f:
            f.write(html_content)
        
        # Return file directly without using after_request
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"vulnerability_scan_{results['scan_info']['target']}_{datetime.datetime.now().strftime('%Y-%m-%d')}.html",
            mimetype='text/html'
        )
        
        # Set cleanup callback
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(temp_file.name)
            except:
                pass
                
        return response

# Fix the abort functionality
@app.route('/api/abort', methods=['POST'])
def abort_scan():
    scan_id = request.args.get('scan_id')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID is required'}), 400
    
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found or already completed'}), 404
    
    # Abort the scan
    try:
        active_scans[scan_id].abort()
        # Remove from active scans
        del active_scans[scan_id]
        return jsonify({'success': True, 'message': 'Scan aborted successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to abort scan: {str(e)}'}), 500

# Simple health check endpoint
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print("Starting RED ALERT Vulnerability Scanner Web Interface...")
    print("Open your browser and navigate to http://localhost:5000")
    
    # Use Flask's built-in server with debug mode
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

