#!/bin/bash

# Farben definieren
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

# Check if a domain argument was passed
if [ -z "$1" ]; then
    echo -e "${RED}[!]${NC} Error: No domain provided. Example usage: ./d2b.sh example.com"
    exit 1
fi

# Banner anzeigen
echo -e "${BLUE}"
echo "============================================"
echo "         domains2burp - d2b.sh"
echo "            Version 0.0.3"
echo "         Created by SirOcram aka 0xFF00FF"
echo "============================================"
echo -e "${NC}"

domain="$1"
domain_domains="${domain}_domains.txt"
domain_live_domains="${domain}_live_domains.txt"

# Überprüfen, ob die domains.txt existiert
if [ -f "$domain_domains" ]; then
    read -p "File $domain_domains already exists. Do you want to overwrite it? (y/n): " choice
    case "$choice" in 
        y|Y ) echo -e "${BLUE}[*]${NC} Overwriting $domain_domains...";;
        n|N ) echo -e "${YELLOW}[+]${NC} Keeping existing file $domain_domains.";;
        * ) echo -e "${RED}[!]${NC} Invalid choice."; exit 1;;
    esac
fi

# Check if assetfinder is installed
if ! command -v assetfinder &> /dev/null
then
    echo -e "${RED}[!]${NC} Error: assetfinder is not installed. Please install it first."
    exit 2
fi

# Check if httprobe is installed
if ! command -v httprobe &> /dev/null
then
    echo -e "${RED}[!]${NC} Error: httprobe is not installed. Please install it first."
    exit 2
fi

# Check if curl is installed
if ! command -v curl &> /dev/null
then
    echo -e "${RED}[!]${NC} Error: curl is not installed. Please install it first."
    exit 2
fi

# Gather subdomains and save to $domain_domains, unless file exists and is not overwritten
if [ ! -f "$domain_domains" ] || [[ "$choice" =~ ^[yY]$ ]]; then
    echo -e "${BLUE}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$domain${NC}..."
    assetfinder --subs-only $domain > "$domain_domains"

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
echo -e "${BLUE}[*]${NC} Checking reachable subdomains with httprobe..."

# Anzahl der Domains zählen
total_domains=$(wc -l < "$domain_domains")
count=0

# Fortschrittsbalken-Schleife
while read -r domain; do
    count=$((count + 1))
    percentage=$((100 * count / total_domains))

    # Zeige den Fortschrittsbalken an
    printf "\r                                                                                                                                                   "
    printf "\r${BLUE}[*]${NC} Testing domain $count of $total_domains: $domain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"

    # Prüfe, ob die Domain erreichbar ist (keine Ausgabe im Terminal)
    echo $domain | httprobe >> "$domain_live_domains"

done < "$domain_domains"

# Zeilenumbruch nach dem Fortschritt
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
echo -e "${BLUE}[*]${NC} Sending reachable domains to Burp Suite Proxy using curl..."

for domain in $(cat "$domain_live_domains"); do
    echo -e "${YELLOW}[+]${NC} Testing $domain"
    curl -x $proxy_url -k $domain
done

echo -e "${GREEN}[+]${NC} All domains were successfully sent to the proxy."
