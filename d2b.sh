#!/bin/bash

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
FUCHSIA="\033[1;35m"
NC="\033[0m" # No Color

VERSION="0.0.4"

# Check if a domain argument was passed
if [ -z "$1" ]; then
    echo -e "${RED}[!]${NC} Error: No domain provided. Example usage: ./d2b.sh example.com"
    exit 1
fi

# Display banner
echo -e "${FUCHSIA}"
echo "============================================"
echo "         domains2burp - d2b.sh"
echo "            Version $VERSION"
echo "         Created by SirOcram aka 0xFF00FF"
echo "============================================"
echo -e "${NC}"

domain="$1"
domain_domains="${domain}_domains.txt"
domain_live_domains="${domain}_live_domains.txt"

# Check if the domains file exists
if [ -f "$domain_domains" ]; then
    read -p "File $domain_domains already exists. Do you want to overwrite it? (y/n): " choice
    case "$choice" in 
        y|Y ) echo -e "${FUCHSIA}[*]${NC} Overwriting $domain_domains...";;
        n|N ) echo -e "${YELLOW}[+]${NC} Keeping existing file $domain_domains.";;
        * ) echo -e "${RED}[!]${NC} Invalid choice."; exit 1;;
    esac
fi

# Check if assetfinder is installed
if ! command -v assetfinder &> /dev/null; then
    echo -e "${RED}[!]${NC} Error: assetfinder is not installed. Please install it first."
    exit 2
fi

# Check if httprobe is installed
if ! command -v httprobe &> /dev/null; then
    echo -e "${RED}[!]${NC} Error: httprobe is not installed. Please install it first."
    exit 2
fi

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    echo -e "${RED}[!]${NC} Error: curl is not installed. Please install it first."
    exit 2
fi

# Gather subdomains and save to $domain_domains, unless file exists and is not overwritten
if [ ! -f "$domain_domains" ] || [[ "$choice" =~ ^[yY]$ ]]; then
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$domain${NC}..."
    assetfinder --subs-only $domain | sort -u > "$domain_domains"  # Sort and remove duplicates

    # Check if $domain_domains was created and has content
    if [ ! -s "$domain_domains" ]; then
        echo -e "${RED}[!]${NC} Error: No subdomains found or $domain_domains is empty."
        exit 3
    fi

    echo -e "${GREEN}[+]${NC} Subdomains successfully saved to $domain_domains."
else
    echo -e "${GREEN}[+]${NC} Skipping subdomain gathering since $domain_domains already exists."
fi

# Filter reachable domains with httprobe and save to $domain_live_domains
echo -e "${FUCHSIA}[*]${NC} Checking reachable subdomains with httprobe..."

# Count the number of domains
total_domains=$(wc -l < "$domain_domains")
count=0

# Clear live_domains.txt before writing
> "$domain_live_domains"

# Progress bar loop
while read -r domain; do
    count=$((count + 1))
    percentage=$((100 * count / total_domains))

    # Display the progress bar
    printf "\r                                                                                                                                                   "
    printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $domain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"

    # Check if the domain is reachable (no output in terminal)
    echo $domain | httprobe >> "$domain_live_domains"

done < "$domain_domains"

# New line after the progress
echo -e "\n${GREEN}[+]${NC} Reachable domains successfully saved to $domain_live_domains."

# Check if $domain_live_domains was created and has content
if [ ! -s "$domain_live_domains" ]; then
    echo -e "${RED}[!]${NC} Error: No reachable domains found or $domain_live_domains is empty."
    exit 4
fi

# Check if Burp Suite proxy is reachable
proxy_url="http://127.0.0.1:8080"
if ! curl -s --head --request GET $proxy_url | grep "200 OK" > /dev/null; then
    echo -e "${RED}[!]${NC} Warning: Burp Suite proxy at $proxy_url is not reachable."
    exit 5
fi

# Send reachable domains to Burp Suite proxy using curl
echo -e "${FUCHSIA}[*]${NC} Sending reachable domains to Burp Suite Proxy using curl..."

# Count the number of live domains
total_live_domains=$(wc -l < "$domain_live_domains")
count=0

for domain in $(cat "$domain_live_domains"); do
    count=$((count + 1))
    echo -e "${YELLOW}[+]${NC} Testing domain $count/$total_live_domains: $domain"
    curl -s -x $proxy_url -k $domain > /dev/null
done

echo -e "${GREEN}[+]${NC} All domains were successfully sent to the proxy."
