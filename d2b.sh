#!/bin/bash



# Farben definieren

GREEN="\033[0;32m"

YELLOW="\033[1;33m"

RED="\033[0;31m"

BLUE="\033[0;34m"

NC="\033[0m" # No Color



# Banner anzeigen

echo -e "${BLUE}"

echo "============================================"

echo "         domains2burp - d2b.sh"

echo "            Version 0.0.1"

echo "         Created by SirOcram aka 0xFF00FF"

echo "============================================"

echo -e "${NC}"



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



# Check if a domain argument was passed

if [ -z "$1" ]; then

    echo -e "${RED}[!]${NC} Error: No domain provided. Example usage: ./d2b.sh example.com"

    exit 1

fi



# Gather subdomains and save to domains.txt

echo -e "${BLUE}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$1${NC}..."

assetfinder --subs-only $1 > domains.txt



# Check if domains.txt was created and has content

if [ ! -s domains.txt ]; then

    echo -e "${RED}[!]${NC} Error: No subdomains found or domains.txt is empty."

    exit 3

fi



echo -e "${GREEN}[+]${NC} Subdomains successfully saved to domains.txt."



# Filter reachable domains with httprobe and save to live_domains.txt

echo -e "${BLUE}[*]${NC} Checking reachable subdomains with httprobe..."



# Anzahl der Domains zählen

total_domains=$(wc -l < domains.txt)

count=0



# Fortschrittsbalken-Schleife

while read -r domain; do

    count=$((count + 1))

    percentage=$((100 * count / total_domains))



    # Zeige den Fortschrittsbalken an

    printf "\r                                                                                                                                                   "

    printf "\r${BLUE}[*]${NC} Testing domain $count of $total_domains: $domain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"



    # Prüfe, ob die Domain erreichbar ist (keine Ausgabe im Terminal)

    echo $domain | httprobe >> live_domains.txt



done < domains.txt



# Zeilenumbruch nach dem Fortschritt

echo -e "\n${GREEN}[+]${NC} Reachable domains successfully saved to live_domains.txt."



# Check if live_domains.txt was created and has content

if [ ! -s live_domains.txt ]; then

    echo -e "${RED}[!]${NC} Error: No reachable domains found or live_domains.txt is empty."

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



for domain in $(cat live_domains.txt); do

    echo -e "${YELLOW}[+]${NC} Testing $domain"

    curl -x $proxy_url -k $domain

done



echo -e "${GREEN}[+]${NC} All domains were successfully sent to the proxy."

