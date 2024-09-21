# d2b.sh
## Domains 2 Burp Suite
This script runns `assetfinder` (thanks [https://github.com/tomnomnom](tomnomnom)) and save live_domains after checking with `httprobe` (also thanks [https://github.com/tomnomnom](tomnomnom)). After the live_domains.txt is saved it will send it to the Burp proxy `127.0.0.1:8080` to list in the sitemap.

## Usage
```bash
./d2b.sh <url>
```
