# Upping
## Overview
Upping is a Python-based tool designed to speed up the reconnaissance phase of a penetration test. It provides automated scanning and enumeration capabilities, leveraging Nmap for port scanning, requests for directory enumeration, and DNS resolver for subdomain enumeration.

## Features
  - Nmap Scanning: Perform quick and detailed Nmap scans to identify open ports and services.
  - Directory Enumeration: Use a wordlist to find directories on a given website.
  - DNS Enumeration: Discover subdomains using a wordlist.

## Prerequisites
  - Python 3.x
    
  Ensure you have the following libraries installed:
  - nmap
  - requests
  - dns.resolver
  - certifi

You can install these dependencies using pip:

` pip install -r requirements.txt `

### Usage

  Clone the repository:

```
git clone <repository_url>
cd <repository_directory>
```
Run the tool:

` python3 upping.py `

Select an option from the menu:
    
    1: Perform an Nmap scan.
    
    2: Enumerate directories on a website. 
  
    3: Enumerate subdomains of a domain. 
  
 
## Example:
### Nmap Scanning
  - Choose option 1 for Nmap scanning.
  - Enter the target IP address.
  
The tool will perform a quick scan to identify open ports, followed by a detailed scan on the identified ports.
Results are saved in scan_results.txt.

### Directory Enumeration
- Choose option 2 for directory enumeration.
- Enter the target website (e.g., https://example.com).
- Provide the path to a wordlist file.

The tool will check each directory in the wordlist and save the results in dir_results.txt.

### DNS Enumeration
  - Choose option 3 for DNS enumeration.
  - Enter the target domain (e.g., example.com).
  - Provide the path to a wordlist file.

The tool will check each subdomain in the wordlist and save the results in list_dns_results.txt.

## Contributing
  Feel free to contribute to this project by submitting a pull request. Ensure your changes are well-documented and tested.

# License
This project is licensed under GNU. See the LICENSE file for details.

### Acknowledgments
  - Nmap: https://nmap.org/
  - Requests: https://docs.python-requests.org/
  - dnspython: https://www.dnspython.org/
  - Certifi: https://certifi.io/
