## Network Sniffer for Basic Vulnerabilities Detection

This Python script utilizes the `scapy` library to sniff network traffic and detect basic vulnerabilities based on packet analysis. It can operate in real-time on a network interface or analyze a pre-recorded PCAP file.

### Features:
- **Vulnerability Detection**: The script identifies several types of network scans and credential leaks:
  - **NULL Scan**: TCP packets with no flags set.
  - **FIN Scan**: TCP packets with only the FIN flag set.
  - **Xmas Scan**: TCP packets with the FIN, PSH, and URG flags set.
  - **Nikto Scan**: Detection of "Nikto" in HTTP request payloads.
  - **HTTP Basic Authentication**: Detection of credentials encoded in Base64 in HTTP headers.
  - **FTP Credentials**: Detection of FTP credentials in FTP commands.
  - **IMAP Credentials**: Detection of IMAP credentials in IMAP commands.
  - **SMB Scan**: Detection of TCP traffic on ports 445 or 139.
  - **RDP Scan**: Detection of TCP traffic on port 3389 (RDP).
  - **VNC Scan**: Detection of TCP traffic on port 5900 (VNC).

### Requirements:
- Python 3
- `scapy` library (`pip install scapy`)
- Root privileges required for live sniffing on network interfaces.

### Usage:
- **Command Line Arguments**:
  - `-i <interface>`: Specify the network interface to sniff on (default is `eth0`).
  - `-r <pcapfile>`: Specify a PCAP file to read instead of live sniffing.

### Examples
To sniff on interface `eth0`: `python sniffer.py -i eth0` <br>
To analyze a PCAP file, use the following command: `python sniffer.py -r example.pcap`

### Output
Detected incidents are printed in the format:
  ALERT #{incident_number}: {incident_detected} is detected from {source_IP} {extra}
  Where:
    - {incident_number}: Sequential number of the incident
    - {incident_detected}: Type of incident detected
    - {source_IP}: Source IP address where the incident originated
    - {extra}: Additional information specific to the incident (e.g., port number)

### Notes
- Ensure proper permissions (sudo or root) when running on a network interface for live sniffing


