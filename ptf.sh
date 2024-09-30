#!/bin/bash

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
FUCHSIA="\033[1;35m"
BLUE="\033[1;34m"
NC="\033[0m" # No Color

# Variables
VERSION="0.0.8"

# Check if a domain argument was passed
if [ -z "$1" ]; then
    echo -e "${RED}[!]${NC} Error: No domain provided. Example usage: $0 example.com"
    exit 1
fi

# Domain arguments
target="$1"
target_domains="domains/${target}/"
target_sub_domains="${target_domains}sub_domains.txt"
target_live_domains="${target_domains}live_domains.txt"
target_redirect_domains="${target_domains}redirect_domains.txt"
screenshots="screenshots/${target}"
proxy_url="http://127.0.0.1:8080"

mkdir -p "$target_domains"

# Display banner
display_banner() {
    echo -e "${FUCHSIA}"
    echo "============================================"
    echo "         PenTestingFramework - ptf.sh"
    echo "            Version $VERSION"
    echo "         Created by SirOcram aka 0xFF00FF"
    echo -e "        For domain: ${YELLOW}$target${NC}"
    echo -e "${FUCHSIA}"
    echo "============================================"
    echo -e "${NC}"
}

# Function: Get all subdomains
get_subdomains() {
    # Assetfinder
    if ! command -v assetfinder &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: assetfinder is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$target${NC}..."
    assetfinder --subs-only "$target" | sort -u > "$target_sub_domains"
    
    # Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: subfinder is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with subfinder for ${YELLOW}$target${NC}..."
    subfinder -d "$target" -all -active -timeout 10 -silent | sort -u >> "$target_sub_domains"
    
    total_domains=$(wc -l < "$target_sub_domains")
    echo -e "${GREEN}[+]${NC} $total_domains subdomains saved to $target_sub_domains"
}

# Amass subdirectoryfinder
get_amass_subdirectories() {
    if ! command -v amass &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: amass is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with amass for ${YELLOW}$target${NC}..."
    amass enum -passive -o "${target_domains}amass.txt" -d "$target"
    
    # Cleaning up ANSI codes
    text=$(cat "${target_domains}amass.txt")
    clean_txt=$(remove_ansi_codes "$text")

    echo "$clean_txt" > "${target_domains}amass.txt"
    echo -e "${GREEN}[+]${NC} Clean text saved to ${target_domains}amass.txt"
    
    echo -e "${FUCHSIA}[*]${NC} Getting subdomains from ${target_domains}amass.txt"
    grep -oP '(?<= --> )([a-zA-Z0-9.-]+\.jura\.ch)' "${target_domains}amass.txt" > "${target_domains}amass_subdomains.txt"
    
    # Sort amass subdomains
    sort -u "${target_domains}amass_subdomains.txt" -o "${target_domains}amass_subdomains.txt"
    
    # Append the findings to the subdomains
    cat "${target_domains}amass_subdomains.txt" | sort -u >> "$target_sub_domains"
    
    # Sort all together
    sort -u "$target_sub_domains" -o "$target_sub_domains"
    
    echo -e "${GREEN}[+]${NC} Subdomains gathered and sorted in $target_sub_domains."
}

# Cleanup ANSI codes function
remove_ansi_codes() {
    local input_text="$1"
    echo "$input_text" | awk '{gsub(/\x1b\[[0-9;]*[a-zA-Z]/, "")}1'
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

# Function remove screenshots
remove_screenshots() {
    echo -e "${RED}[!]${NC} Removing all screenshots from ${screenshots}."
    rm -rf $screenshots
    if [ ! -d $screenshots ]; then
    	echo -e "${GREEN}[+]${NC} Screenshots are successfully removed."
    fi
}

# Function: Take screenshots
take_screenshots() {
    if ! command -v gowitness &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: gowitness is not installed. Please install it first."
        return 1
    fi
    if [ ! -d $screenshots ]; then
    	echo -e "${GREEN}[+]${NC} making missing screenshots directory under: ${screenshots}."
	mkdir -p $screenshots
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of live domains with gowitness..."
    gowitness scan file -f "$target_live_domains" -s "$screenshots"
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of redirected domains with gowitness..."
    gowitness scan file -f "$target_redirect_domains" -s "$screenshots"
    
    total_files=$(ls -1 "$screenshots" | wc -l)
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
    pattern="${target_domains}*"

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
    echo "1. Get all subdomains (assetfinder, subfinder)"
    echo "2. Get amass subdomains (amass)"
    echo "3. Check for live domains (httprobe)"
    echo "4. Handle redirects"
    echo "5. Remove screenshots"
    echo "6. Take screenshots (gowitness)"
    echo "7. Import in Burp (burp/proxy)"
    echo "8. Get open ports (nmap)"
    echo "9. Cleanup files"
    echo "x. Exit"
    read -p "Select an option: " option

    # Execute based on user selection
    case $option in
        a)
            get_subdomains
            get_amass_subdirectories
            check_live_domains
            handle_redirects
            take_screenshots
            import_in_burp
            get_open_ports
            ;;
        1)
            get_subdomains
            ;;
        2)
            get_amass_subdirectories
            ;;
        3)
            check_live_domains
            ;;
        4)
            handle_redirects
            ;;
        5)
            remove_screenshots
            ;;
        6)
            take_screenshots
            ;;
        7)
            import_in_burp
            ;;
        8)
            get_open_ports
            ;;
        9)
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
