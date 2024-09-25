#!/bin/bash

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
FUCHSIA="\033[1;35m"
NC="\033[0m" # No Color

# Variables
VERSION="0.0.5"
CUSTOM_HEADER="Pentester SirOcram: Bugbounty - Switzerland"

# Check if a domain argument was passed
if [ -z "$1" ]; then
    echo -e "${RED}[!]${NC} Error: No domain provided. Example usage: ./ptf.sh example.com"
    exit 1
fi

# Domain argument
domain="$1"
domain_domains="${domain}_domains.txt"
domain_live_domains="${domain}_live_domains.txt"
proxy_url="http://127.0.0.1:8080"

# Display banner
display_banner() {
    echo -e "${FUCHSIA}"
    echo "============================================"
    echo "         PenTestingFramework - ptf.sh"
    echo "            Version $VERSION"
    echo "         Created by SirOcram aka 0xFF00FF"
    echo -e "        For domain: ${YELLOW}$domain${NC}"
    echo "============================================"
    echo -e "${NC}"
}

# Function: Get all subdomains
get_subdomains() {
    if ! command -v assetfinder &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: assetfinder is not installed. Please install it first."
        return 1
    fi
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$domain${NC}..."
    assetfinder --subs-only "$domain" | sort -u > "$domain_domains"
}

# Function: Check for live domains
check_live_domains() {
    if ! command -v httprobe &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: httprobe is not installed. Please install it first."
        return 1
    fi
    echo -e "${FUCHSIA}[*]${NC} Checking reachable subdomains with httprobe..."

    total_domains=$(wc -l < "$domain_domains")
    count=0

    > "$domain_live_domains" # Clear live domains file

    while read -r subdomain; do
        count=$((count + 1))
        percentage=$((100 * count / total_domains))
        printf "\r                                                                                                  "
        printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $subdomain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"
        echo "$subdomain" | httprobe >> "$domain_live_domains"
    done < "$domain_domains"
    echo
}

# Function: Check the scope for live domains
check_scope() {
    if ! command -v ipcalc &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: ipcalc is not installed. Please install it first."
        return 1
    fi

    # Load the configuration file
    if [ ! -f config.txt ]; then
        echo -e "${RED}[!]${NC} Error: config.txt not found!"
        return 1
    fi

    source config.txt

    # Check if the live domains file exists
    if [ ! -f "$domain_live_domains" ]; then
        echo -e "${RED}[!]${NC} Error: Live domains file ($domain_live_domains) not found!"
        return 1
    fi

    echo -e "${FUCHSIA}[*]${NC} Checking the scope for live domains using ipcalc..."

    # Iterate through each live domain
    while read -r live_domain; do
        # Remove http:// and https:// prefixes
        clean_domain=$(echo "$live_domain" | sed 's~http[s]*://~~g')

        # Resolve domain to IP
        live_domain_ip=$(dig +short "$clean_domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

        if [ -z "$live_domain_ip" ]; then
            echo -e "${RED}[!]${NC} Error: Unable to resolve IP for domain $clean_domain."
            continue
        fi

        echo -e "${FUCHSIA}[*]${NC} Checking the scope for ${YELLOW}$clean_domain (${live_domain_ip})${NC}..."

        # Assume the domain is out of scope unless proven otherwise
        in_scope=false
        out_scope=false

        # Check if the IP falls within any of the out-of-scope ranges
        for scope in "${OUT_OF_SCOPE[@]}"; do
            if ipcalc -r "$live_domain_ip" "$scope" &> /dev/null; then
                echo -e "${RED}[!]${NC} $live_domain_ip is out of scope (${scope})."
                out_scope=true
                break
            fi
        done

        # Check if the IP falls within any of the in-scope ranges
        if [ "$out_scope" = false ]; then
            for scope in "${IN_SCOPE[@]}"; do
                if ipcalc -r "$live_domain_ip" "$scope" &> /dev/null; then
                    echo -e "${GREEN}[+]${NC} $live_domain_ip is in scope (${scope})."
                    in_scope=true
                    break
                fi
            done
        fi

        # If no match for in-scope or out-of-scope, it is out of scope by default
        if [ "$in_scope" = false ] && [ "$out_scope" = false ]; then
            echo -e "${RED}[!]${NC} $live_domain_ip is out of scope."
        fi

    done < "$domain_live_domains"

    return 0
}

# Function: Import in Burp
import_in_burp() {
    if ! curl -s --head --request GET -H "$CUSTOM_HEADER" "$proxy_url" | grep "200 OK" > /dev/null; then
        echo -e "${RED}[!]${NC} Warning: Burp Suite proxy at $proxy_url is not reachable."
        return 1
    fi
    echo -e "${FUCHSIA}[*]${NC} Sending reachable domains to Burp Suite Proxy using curl..."

    total_live_domains=$(wc -l < "$domain_live_domains")
    count=0

    for live_domain in $(cat "$domain_live_domains"); do
        count=$((count + 1))
        echo -e "${YELLOW}[+]${NC} Sending domain $count/$total_live_domains: $live_domain"
        curl -s -x "$proxy_url" -k -H "$CUSTOM_HEADER" "$live_domain" > /dev/null
    done

    echo -e "${GREEN}[+]${NC} All domains were successfully sent to the proxy."
}

# Function: Take screenshots
take_screenshots() {
    if ! command -v gowitness &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: gowitness is not installed. Please install it first."
        return 1
    fi
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of live domains with gowitness..."
    gowitness --disable-db file -f "$domain_live_domains"
}

# Function: Get open ports
get_open_ports() {
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: nmap is not installed. Please install it first."
        return 1
    fi
    echo -e "${FUCHSIA}[*]${NC} Scanning for open ports with nmap..."
    sudo nmap -sS -sV -O -oN "${domain}_open_ports.txt" -vv -p- -T3 --script=default --open --min-rate=100 --max-retries=3 -iL "$domain_live_domains"
}

# Loop to show menu after each task
while true; do
    display_banner
    # Menu
    echo "1. Run all"
    echo "2. Get all subdomains (assetfinder)"
    echo "3. Check for live domains (httprobe)"
    echo "4. Check the scope (ipcalc)"
    echo "5. Import in Burp"
    echo "6. Take screenshots"
    echo "7. Get open ports"
    echo "x. Exit"
    read -p "Select an option: " option

    # Execute based on user selection
    case $option in
        1)
            get_subdomains
            check_live_domains
            check_scope
            import_in_burp
            take_screenshots
            get_open_ports
            ;;
        2)
            get_subdomains
            ;;
        3)
            check_live_domains
            ;;
        4)
            check_scope
            ;;
        5)
            import_in_burp
            ;;
        6)
            take_screenshots
            ;;
        7)
            get_open_ports
            ;;
        x)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}[!]${NC} Invalid option."
            ;;
    esac

    sleep 2
done
