# Pentester Recon Tool - v1.3.0 - WIP

## Usage
```bash
./prt.sh <url>
```

### Main Menu
```
==================== Main Menu =====================
1. Subdomain Enumeration and Reconnaissance
2. Domain Check and Scope Handling
3. Security Tests
4. Reporting and Import
5. Cleanup
x. Exit
```
### Subdomain Enumeration
```
===== Subdomain Enumeration and Reconnaissance =====
1. Get all subdomains (assetfinder, subfinder)
2. Get theHarvester entries
3. Get WaybackURLs
x. Back to Main Menu
```
### Domain Check and Scope Handling
```
========= Domain Check and Scope Handling ==========
1. Handle redirects
2. Check scopes
3. Check for live domains (httprobe)
x. Back to Main Menu
```
### Security Tests
```
================== Security Tests ==================
1. Check CSP
2. Check XSS with Dalfox
x. Back to Main Menu
```
### Reporting
```
=============== Reporting and Import ===============
1. Generate report of CSP
2. Generate report of XSS
3. Take screenshots (gowitness)
4. Generate HTML output of screenshots
5. Import into Burp Suite
6. Quick host up check (IP/range nmap)
7. Generate HTML output of up hosts
8. Get open ports (nmap)
9. Generate report of open ports
10. Check for downloads
11. Generate preview of downloads
x. Back to Main Menu
```
### Cleanup
```
===================== Cleanup ======================
1. Cleanup all files
2. Cleanup domains
3. Cleanup downloads
4. Cleanup nmap
5. Cleanup screenshots
6. Cleanup security
7. Cleanup theHarvester
8. Cleanup waybackURLs
```

## CSP scan report
![image](https://github.com/user-attachments/assets/d3e9643c-321e-42ff-a239-13f25f3cf0a1)

## XSS scan report
![image](https://github.com/user-attachments/assets/bd5d0d00-d5d5-451e-85ff-649c116cbd61)

## Screenshots
![image](https://github.com/user-attachments/assets/8f010c1f-cfdf-447e-8d75-d5810da4ee79)

## nmap scan results
![image](https://github.com/user-attachments/assets/02a1cc3a-cf03-4888-8820-b26bf42f8401)

## Downloaded files
![image](https://github.com/user-attachments/assets/231f0a26-f7e2-43fe-ab1e-19be2f200ff7)

## Workflow
![PentesterReconTool drawio](https://github.com/user-attachments/assets/6e625999-1331-4d0d-950a-22f25b238d87)

### ToDos
- [x] Subdomain Enumeration and Reconnaissance
    - [x] Get all subdomains (assetfinder, subfinder, sublist3r)
    - [x] Get theHarvester entries
    - [x] Get WaybackURLs
- [x] Domain Check and Scope Handling
    - [x] Handle redirects
    - [x] Check scopes
    - [x] Check for live domains (httprobe)
    - [x] Get URL parameters for dalfox (paramspider)
    - [x] Get API version
    - [x] Get API response
- [ ] Security Tests
    - [x] Check CSP
    - [x] Check XSS with Dalfox
    - [ ] Check for prototype pollution
- [ ] Reporting and Import
    - [x] Generate report of CSP
    - [x] Generate report of XSS
    - [x] Take screenshots (gowitness)
    - [x] Generate HTML output of screenshots
    - [x] Import into Burp Suite
    - [x] Quick host up check (IP/range nmap)
    - [x] Generate HTML output of up hosts
    - [x] Get open ports (nmap)
    - [x] Generate report of open ports
    - [x] Check for downloads
    - [ ] Generate preview of downloads
- [x] Cleanup
    - [x] Cleanup all files
    - [x] Cleanup domains
    - [x] Cleanup downloads
    - [x] Cleanup nmap
    - [x] Cleanup screenshots
    - [x] Cleanup security
    - [x] Cleanup theHarvester
    - [x] Cleanup waybackURLs
    - [x] Cleanup APIs
