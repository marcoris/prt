#!/bin/bash

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
FUCHSIA="\033[1;35m"
BLUE="\033[1;34m"

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
target="domains/$1"
target_sub_domains="${target}_sub_domains.txt"
target_live_domains="${target}_live_domains.txt"
target_protocol_domains="${target}_live_protocol_domains.txt"
target_redirect_domains="${target}_redirect_domains.txt"
proxy_url="http://127.0.0.1:8080"

# Display banner
display_banner() {
    echo -e "${FUCHSIA}"
    echo "============================================"
    echo "         PenTestingFramework - ptf.sh"
    echo "            Version $VERSION"
    echo "         Created by SirOcram aka 0xFF00FF"
    echo -e "        For domain: ${YELLOW}$target${NC}"
    echo "============================================"
    echo -e "${NC}"
}

# Function: Get all subdomains
get_subdomains() {
    if ! command -v assetfinder &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: assetfinder is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$target${NC}..."
    assetfinder --subs-only "$target" | sort -u > "$target_sub_domains"
    total_domains=$(wc -l < "$target_sub_domains")
    echo -e "${GREEN}[+]${NC} $total_domains subdomains saved to $target_sub_domains"
}

# Function: Check for live domains
check_live_domains() {
    if ! command -v httprobe &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: httprobe is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Checking reachable subdomains with httprobe..."

    total_domains=$(wc -l < "$target_sub_domains")
    count=0

    > "$target_live_domains" # Clear live domains file

    while read -r subdomain; do
        count=$((count + 1))
        percentage=$((100 * count / total_domains))
        printf "\r                                                                                                  "
        printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $subdomain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"
        echo "$subdomain" | httprobe >> "$target_live_domains"
    done < "$target_sub_domains"
    
    total_live_domains=$(wc -l < "$target_live_domains")
    
    printf "\r\n"
    echo -e "${GREEN}[+]${NC} $total_live_domains live subdomains saved to $target_live_domains"
}

# Function: Handle Redirects
handle_redirects() {
    echo -e "${BLUE}[i]${NC} Active scan with header $CUSTOM_HEADER..."
    echo -e "${GREEN}[+]${NC} Handle redirects with curl and save subdomains to $target_redirect_domains"
    total_domains=$(wc -l < "$target_live_domains")
    count=0
    
    > "$target_redirect_domains"
    
    while read -r url; do
        count=$((count + 1))
        
        # Use curl to follow redirects and get the final URL
        final_url=$(curl -s -o /dev/null -w "%{url_effective}" -k -L "$url")
        # Remove the :443 port if it exists
    	final_url=$(echo "$final_url" | sed 's/:443//')
    	# Remove trailing slash if it exists
    	final_url=$(echo "$final_url" | sed 's/\/\+$//')
        
        printf "\r                                                                                                  "
        printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $url"

        # Check if there is a new URL after the redirect
        if [ "$final_url" != "$url" ]; then            
            # Save the final URL with its original protocol to the live domains file
            echo "$final_url" >> "$target_redirect_domains"
        else
            # If no redirect, save the original URL
            echo "$url" >> "$target_redirect_domains"
        fi
    done < "$target_live_domains"
    
    sort -u "$target_redirect_domains" -o "$target_redirect_domains"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    printf "\r\n"
    echo -e "${GREEN}[+]${NC} $total_redirect_domains live subdomains saved to $target_redirect_domains"
}

# Function: Import in Burp
import_in_burp() {
    if ! curl -s --head --request GET -H "$CUSTOM_HEADER" "$proxy_url" | grep "200 OK" > /dev/null; then
        echo -e "${RED}[!]${NC} Warning: Burp Suite proxy at $proxy_url is not reachable."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Active scan with header $CUSTOM_HEADER..."
    echo -e "${FUCHSIA}[*]${NC} Sending reachable domains to Burp Suite Proxy using curl..."

    total_live_domains=$(wc -l < "$target_redirect_domains")
    count=0

    for live_domain in $(cat "$target_live_domains"); do
        count=$((count + 1))
        echo -e "${YELLOW}[+]${NC} Sending domain $count/$total_live_domains: $live_domain"
        curl -s -x "$proxy_url" -k -H "$CUSTOM_HEADER" "$live_domain" > /dev/null
    done

    echo -e "${GREEN}[+]${NC} $count domains were successfully sent to the proxy."
}

# Function: Take screenshots
take_screenshots() {
    if ! command -v gowitness &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: gowitness is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of live domains with gowitness..."
    gowitness --disable-db file -f "$target_live_domains"
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of redirected domains with gowitness..."
    gowitness --disable-db file -f "$target_redirect_domains"
    total_files=$(ls -1 "screenshots" | wc -l)
    echo -e "${BLUE}[i]${NC} $total_files screenshots were made."
}

# Function: Get open ports
get_open_ports() {
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: nmap is not installed. Please install it first."
        return 1
    fi
    echo -e "${RED}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Scanning for open ports with nmap..."
    
    # Loop through each live domain in the input file
    while read -r target; do
        # Use a safe filename by replacing unwanted characters
        safe_target=$(echo "$target" | tr -s '[:punct:]' '_' | tr ' ' '_')
    
        # Run Nmap scan and save output to a file named after the domain
        sudo nmap -sS -sV -O -oN "${safe_target}_open_ports.txt" -vv -p- -T3 --script=default --open --min-rate=50 --max-retries=3 "$target"
    done < "$target_live_domains"

}

# Function to clean up files
cleanup() {
     # Define the pattern to match files with prefix $target_
    pattern="${target}_*"

    echo -e "${YELLOW}[*]${NC} Cleaning up files for target: ${YELLOW}$target${NC}..."

    # Remove files matching the pattern
    rm -f $pattern 2>/dev/null

    # Check if any files were deleted
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+]${NC} Removed all files."
    else
        echo -e "${RED}[!]${NC} No files found."
    fi
}

# Loop to show menu after each task
while true; do
    display_banner
    # Menu
    echo "a. Run all"
    echo "2. Get all subdomains (assetfinder)"
    echo "3. Check for live domains (httprobe)"
    echo "4. Handle redirects"
    echo "5. Import in Burp"
    echo "6. Take screenshots"
    echo "7. Get open ports"
    echo "8. Cleanup files"
    echo "x. Exit"
    read -p "Select an option: " option

    # Execute based on user selection
    case $option in
        a)
            get_subdomains
            check_live_domains
            handle_redirects
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
            handle_redirects
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
        8)
            cleanup
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
