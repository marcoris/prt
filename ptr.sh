#!/bin/bash

# Variables
VERSION="1.3.0"
PORT="8080"
proxy_url="http://127.0.0.1:${PORT}"
HEADER="X-Bugbounty-Switzerland: USERNAME"
DALFOXHEADER="--header \"$HEADER\""
get_last_years=3
allowed_types=(
    "application/pdf"
    "application/zip"
    "application/json"
    "application/xml"
    "application/octet-stream"
    "text/plain"
    "application/msword"
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    "application/vnd.ms-excel"
    "image/jpeg"
    "image/png"
    "image/gif"
    "audio/mpeg"
    "audio/wav"
    "video/mp4"
)
tools=(
    assetfinder
    amass
    csp
    dalfox
    grepcidr
    gowitness
    httprobe
    jq
    nmap
    sublist3r
    subfinder
    theHarvester
    waybackurls
)

# Define colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
FUCHSIA="\033[1;35m"
BLUE="\033[1;34m"
NC="\033[0m" # No Color

# Check if a domain argument was passed
if [ -z "$1" ]; then
    echo -e "${RED}[!]${NC} Error: No domain provided. Example usage: $0 example.com"
    exit 1
fi

# Check if all required commands are installed
for cmd in $tools; do
    if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}[!]${NC} $cmd is not installed. Please install it first."
    exit 1
    fi
done

# Domain/file arguments
target="$1"
target_domains="../${target}/domains/"
target_sub_domains="${target_domains}sub_domains.txt"
amass_sub_domains="${target_domains}amass_sub_domains.txt"
target_live_domains="${target_domains}live_domains.txt"
target_redirect_domains="${target_domains}redirect_domains.txt"
target_redirect_for_scope_domains="${target_domains}redirect_for_scope_domains.txt"
in_scope_results="${target_domains}in_scope_subdomains.txt"
out_of_scope_results="${target_domains}out_of_scope_subdomains.txt"
no_data_results="${target_domains}no_data_subdomains.txt"

# Directory/file arguments
the_harvester_files="../$target/theharvester/"
target_theharvester="${the_harvester_files}theHarvester.json"
download_files="../$target/downloads/"
waybackurls_files="../$target/waybackurls/"
screenshots="../$target/screenshots/"
security="../$target/security/"
xss_files="${security}xss/vulnerabilities.txt"
csp_files="${security}csp/"
csp_has_file="${csp_files}has/"
csp_has_json="${csp_files}has/validation.json"
csp_no_file="${csp_files}no/"
nmap="../$target/nmap/"
nmap_ports="${nmap}ports/"
nmap_hosts="${nmap}hosts/"
output_html_open_ports="${nmap_ports}open_ports.html"
output_html_screenshots="${screenshots}screenshots.html"
output_html_csp="${csp_has_file}validation.html"

# Scope files
in_scope="../$target/in_scope.txt"
out_of_scope="../$target/out_of_scope.txt"

# Make directories
mkdir -p $target_domains
mkdir -p $the_harvester_files
mkdir -p $download_files
mkdir -p $waybackurls_files
mkdir -p $screenshots
mkdir -p $nmap_ports
mkdir -p $nmap_hosts
mkdir -p $csp_has_file
mkdir -p $csp_no_file

display_banner() {
    echo -e "${FUCHSIA}============================================"
    echo ""
    echo "             Pentester Recon Tool"
    echo "            Version $VERSION"
    echo "      Created by SirOcram aka 0xFF00FF"
    echo -e "       For domain: ${YELLOW}$target${NC}"
    echo ""
    echo -e "${FUCHSIA}============================================${NC}"
}

get_subdomains() {    
    > $target_sub_domains
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$target${NC}..."
    assetfinder --subs-only $target | sort -u >> $target_sub_domains

    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with subfinder for ${YELLOW}$target${NC}..."
    subfinder -d $target -all -active -timeout 10 -silent | sort -u >> $target_sub_domains
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with sublist3r for ${YELLOW}$target${NC}..."
    sublist3r -e google.com,yahoo.com,bing.com,ask.com,netcraft.com,dnsdumpster.com,threatcrowd.com,passivedns.com,crt.sh -d $target -o "${target_domains}sublist3r.txt"
    
    cat "${target_domains}sublist3r.txt" >> $target_sub_domains
    
    rm "${target_domains}sublist3r.txt"
    
    sort -u $target_sub_domains -o $target_sub_domains
    
    total_domains=$(wc -l < "$target_sub_domains")
    echo -e "${GREEN}[+]${NC} $total_domains subdomains saved to $target_sub_domains"
}

get_amass_subdirectories() {   
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with amass for ${YELLOW}$target${NC}..."
    amass enum -passive -d $target -o "${target_domains}amass.txt"
    
    # Cleaning up ANSI codes
    text=$(cat "${target_domains}amass.txt")
    clean_txt=$(cleanup_ansi_codes "$text")
    echo "$clean_txt" > "${target_domains}amass.txt"
    echo -e "${GREEN}[+]${NC} Clean text saved to ${target_domains}amass.txt"
    
    # Extract only IP addresses from Netblock entries and save to the cleaned file
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "${target_domains}amass.txt" > "${target_domains}amass_cleaned.txt"

    # Extract only netblocks from ASN announces entries and append to the cleaned file
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "${target_domains}amass.txt" >> "${target_domains}amass_cleaned.txt"

    # Remove duplicates and sort the cleaned file
    cat "${target_domains}amass_cleaned.txt" >> $amass_sub_domains

    # Remove duplicates and sort the cleaned file
    cat $amass_sub_domains >> $target_sub_domains

    # Sort results
    sort -u $target_sub_domains -o $target_sub_domains
    
    total_domains=$(wc -l < $target_sub_domains)
    echo -e "${GREEN}[+]${NC} $total_domains Subdomains gathered and sorted in ${target_sub_domains}."
}

cleanup_ansi_codes() {
    local input_text="$1"
    echo "$input_text" | awk '{gsub(/\x1b\[[0-9;]*[a-zA-Z]/, "")}1'
}

get_theharvester_data() {
    echo -e "${BLUE}[i]${NC} Passive scan..."
	limit=500
	echo -e "${FUCHSIA}[*]${NC} Fetching subdomains with theHarvester..."
    start=$(date +%s)
	theHarvester -d $target -b all -l "$limit" -n -f theharvester
	start=$(date +%s)

    email_count=$(jq -r '.emails[] | select(. != null)' theharvester.json | wc -l)
	subdomain_count=$(jq -r '.hosts[] | select(. != null)' theharvester.json | wc -l)
    interesting_urls_count=$(jq -r '.interesting_urls[] | select(. != null)' theharvester.json | wc -l)
    ip_count=$(jq -r '.ips[] | select(. != null)' theharvester.json | wc -l)
    
    echo -e "${GREEN}[+]${NC} Took $(($end-$start)) seconds to fetch theharvester data."
    echo -e "${GREEN}[+]${NC} $email_count E-Mails fetched."
	echo -e "${GREEN}[+]${NC} $subdomain_count Subdomains fetched."
    echo -e "${GREEN}[+]${NC} $interesting_urls_count Interesting URLs fetched."
    echo -e "${GREEN}[+]${NC} $ip_count IPs fetched."
        
    while true; do
        echo -e "${YELLOW}[*]${NC} Would you like to handle the data? (Y/n)"
        read -r answer

        answer=${answer:-y}

        if [[ "$answer" =~ ^[Yy]$ ]]; then
            handle_theharvester_data
            break
        elif [[ "$answer" =~ ^[Nn]$ ]]; then
            echo -e "${YELLOW}[*]${NC} Would you instead like to delete the data? (y/N)"
            read -r answer2

            answer2=${answer2:-n}

            if [[ "$answer2" =~ ^[Yy]$ ]]; then
                rm theharvester.xml
                rm theharvester.json
                break
            elif [[ "$answer2" =~ ^[Nn]$ ]]; then
                echo -e "${YELLOW}[*]${NC} No action taken. Exiting the loop."
                break
            fi
        else
            echo -e "${YELLOW}[*]${NC} Invalid input. Please answer with 'y' or 'n'."
        fi
    done

}

handle_theharvester_data() {
    mv theharvester.json $target_theharvester
    rm theharvester.xml
	
	jq -r '.emails[] | select(. != null)' "$target_theharvester" > "${the_harvester_files}emails.txt"
    jq -r '.hosts[] | select(. | test("^[^:]+$"))' "$target_theharvester" > "${the_harvester_files}sub_domains.txt"
    jq -r '.interesting_urls[] | select(. != null)' "$target_theharvester" > "${the_harvester_files}interesting_urls.txt"
	jq -r '.ips[] | select(. != null)' $target_theharvester > "${the_harvester_files}ips.txt"
	
    total_domains_before=$(wc -l < $target_sub_domains)
    total_redirect_domains_before=$(wc -l < $target_redirect_domains)

	cat "${the_harvester_files}sub_domains.txt" >> $target_sub_domains

    sort -u $target_sub_domains -o $target_sub_domains

    cat "${the_harvester_files}interesting_urls.txt" >> $target_redirect_domains
	
    total_domains_after=$(wc -l < $target_sub_domains)
    echo -e "${GREEN}[+]${NC} $total_domains_before Subdomains before and $total_domains_after subdomains after are saved in $target_sub_domains"
    
    total_redirect_domains=$(wc -l < $target_redirect_domains)
    echo -e "${GREEN}[+]${NC} $total_redirect_domains_before Redirected domains before and $total_redirect_domains Interesting domains after are saved in $target_redirect_domains"

    total_emails=$(wc -l < "${the_harvester_files}emails.txt")
    echo -e "${GREEN}[+]${NC} $total_emails E-mails are saved in ${the_harvester_files}emails.txt"
}

get_wayback_urls() {
    echo -e "${BLUE}[i]${NC} Passive scan..."
    > "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt"
    start=$(date +%s)
	echo -e "${FUCHSIA}[*]${NC} Subdomains to fetch with WaybackURLs. This can take a while..."
	echo $target | waybackurls -dates | sort -u > "${waybackurls_files}waybackurls_raw.txt"
    end=$(date +%s)
	total_domains=$(wc -l < "${waybackurls_files}waybackurls_raw.txt")
    start_date=$(head -1 "${waybackurls_files}waybackurls_raw.txt" | awk '{print $1}')
    end_date=$(tail -1 "${waybackurls_files}waybackurls_raw.txt"| awk '{print $1}')
	echo -e "${GREEN}[+]${NC} Took $(($end-$start)) seconds to fetch $total_domains domains which are saved in ${waybackurls_files}waybackurls_raw.txt"
	echo -e "${GREEN}[+]${NC} From starting date $start_date till end date $end_date"
    echo -e "${FUCHSIA}[*]${NC} Saving data since $get_last_years years ago..."

    # loop through last 3 years and cut off the old ones
    current_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    x_years_ago=$(date -u -d "$current_date - $get_last_years years" +"%Y-%m-%dT%H:%M:%SZ")

    mapfile -t lines < "${waybackurls_files}waybackurls_raw.txt"
    start_index=$(binary_search "$x_years_ago")
    for (( i=start_index; i<${#lines[@]}; i++ )); do
        echo "${lines[$i]}" >> "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt"
    done

    # remove the dates and save to waybackurls.txt
    cat "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt" | awk '{print $2}' | sort -u > "${waybackurls_files}waybackurls.txt"

    # check for keywords and save them in waybackurls/KEYWORD.txt (user, passw, admin, ...)
    keywords=(
        "api"
        "user"
        "passw"
    )

    for keyword in "${keywords[@]}"; do
        output_file="${waybackurls_files}${keyword}.txt"
        grep -i "$keyword" "${waybackurls_files}waybackurls.txt" > "${output_file}"
        total_domains=$(wc -l < "${output_file}")
        echo -e "${FUCHSIA}[*]${NC} $total_domains domains with keyword $keyword saved in $output_file"
    done

    total_domains_before=$(wc -l < $target_sub_domains)

    # export the subdomins
    while IFS= read -r url; do
        if [[ "$url" =~ ^https?://([^/]+) ]]; then
            domain="${BASH_REMATCH[1]}"
            IFS='.' read -ra parts <<< "$domain"
            main_domain="${parts[-2]}.${parts[-1]}"
            echo "$main_domain" >> "$target_sub_domains"

            if [ ${#parts[@]} -gt 2 ]; then
                echo "$domain" >> "$target_sub_domains"
            fi
        fi
    done < "${waybackurls_files}waybackurls.txt"

    sort -u "$target_sub_domains" -o "$target_sub_domains"

    total_domains_after=$(wc -l < $target_sub_domains)
    echo -e "${GREEN}[+]${NC} $total_domains_before Subdomains before and $total_domains_after subdomains after are saved in $target_sub_domains"
}

check_for_downloads() {
    echo -e "${FUCHSIA}[*]${NC} Checking for downloadable files..."

    # check the files to and download
    while IFS= read -r url; do
        if is_downloadable "$url"; then
            filename=$(basename "$url")
            echo -e "${FUCHSIA}[*]${NC} Downloading file: $filename ($url)"
            curl -o "$download_files/$filename" "$url" -H $HEADER
        fi
        sleep 1
    done < "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt"
}

is_downloadable() {
    local url=$1
    local content_type=$(curl -sI "$url" -H "$HEADER" | grep -i "Content-Type:" | cut -d' ' -f2 | tr -d '\r')

    if [ "$content_type" ]; then
        for type in "${allowed_types[@]}"; do
            echo "content_type: $content_type"
            echo "type: $type"
            if [[ "$content_type" == "$type" ]]; then
                return 0
            fi
        done
    fi
    return 1
}

# Function to get the date from 1998-12-01T06:00:43Z URL
get_date_from_line() {
    echo "$1" | cut -d' ' -f1
}

binary_search() {
    local x_years_ago="$1"
    local low=0
    local high=$((${#lines[@]} - 1))
    local mid
    while [[ $low -le $high ]]; do
        mid=$(( (low + high) / 2 ))
        line_date=$(get_date_from_line "${lines[$mid]}")
        
        if [[ "$line_date" < "$x_years_ago" ]]; then
            low=$((mid + 1))
        else
            high=$((mid - 1))
        fi
    done
    echo $low
}

check_scopes() {   
    total_sub_domains=$(wc -l < "$target_redirect_for_scope_domains")
    
    echo -e "${FUCHSIA}[*]${NC} Checking $total_sub_domains subdomains for scope..."

	> "$in_scope_results"
	> "$out_of_scope_results"
	> "$no_data_results"

	if [[ ! -f "$in_scope" || ! -f "$out_of_scope" || ! -f "$target_redirect_for_scope_domains" ]]; then
        echo -e "${RED}[!]${NC} At least one file is missing!"
        exit 1
	fi

	while IFS= read -r subdomain; do
        ip=$(dig +short "$subdomain")
        
        if [[ -z "$ip" ]]; then
            echo "$subdomain" >> "$no_data_results"
            continue
        fi

        if [[ -s "$in_scope" ]]; then
            if echo "$ip" | grepcidr -f "$in_scope" > /dev/null; then
                echo "$subdomain" >> "$in_scope_results"
            else
                echo "$subdomain" >> "$out_of_scope_results"
            fi
        else
            if echo "$ip" | grepcidr -f "$out_of_scope" > /dev/null; then
                echo "$subdomain" >> "$out_of_scope_results"
            else
                echo "$subdomain" >> "$in_scope_results"
            fi
        fi
	done < "$target_redirect_for_scope_domains"
    
    total_in_scope_domains=$(wc -l < "$in_scope_results")
    total_out_scope_domains=$(wc -l < "$out_of_scope_results")
    total_no_data_domains=$(wc -l < "$no_data_results")

    echo -e "${GREEN}[+]${NC} ${total_in_scope_domains} Subdomains are in scope."
    echo -e "${GREEN}[+]${NC} ${total_out_scope_domains} Subdomains are not in scope."
    echo -e "${GREEN}[+]${NC} ${total_no_data_domains} Subdomains are not callable."
}

check_xss() {
	echo -e "${RED}[!]${NC} Active scanning for XSS vulnerabilities..."
    
    if [ -z "$HEADER" ]; then
        cat "${target_live_domains}" | dalfox pipe --silence --waf-evasion --output $xss_files
    else
        cat "${target_live_domains}" | dalfox pipe --silence --waf-evasion $HEADER --output $xss_files
    fi
}

check_live_domains() {
    total_domains=$(wc -l < "$in_scope_results")
    count=0

    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Checking $total_domains reachable and in scope subdomains with httprobe..."
    
    > $target_live_domains
    
    if [[ $total_domains -gt 0 ]]; then
        while read -r subdomain; do
            ((count++))
            percentage=$((100 * count / total_domains))
            printf "\r                                                                                                  "
            printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $subdomain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"
            echo "$subdomain" | httprobe >> "$target_live_domains"
        done < "$in_scope_results"
    fi
    
    total_live_domains=$(wc -l < "$target_live_domains")
    
    printf "\r\n"
    echo -e "${GREEN}[+]${NC} $total_live_domains live subdomains saved to $target_live_domains"
}

handle_redirects() {
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${GREEN}[+]${NC} Handle redirects with curl and save subdomains to $target_redirect_domains"
    total_domains=$(wc -l < "$target_sub_domains")
    count=0
    
    > "$target_redirect_domains"
    > "$target_redirect_for_scope_domains"
    
    if [[ $total_domains -gt 0 ]]; then
	    while read -r url; do
            ((count++))
            
            # Use curl to follow redirects and get the final URL
            final_url=$(curl --connect-timeout 10 -s -o /dev/null -w "%{url_effective}" -k -L "$url" -H "$HEADER")
            # Remove the :443 port if it exists
            final_url=$(echo "$final_url" | sed 's/:443//')
            # Remove trailing slash if it exists
            final_url=$(echo "$final_url" | sed 's/\/\+$//')
            
            printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $url"

            # Check if there is a new URL after the redirect
            if [ "$final_url" != "$url" ]; then            
                # Save the final URL with its original protocol to the live domains file
                echo "$final_url" >> "$target_redirect_domains"
            else
                # If no redirect, save the original URL
                echo "$url" >> "$target_redirect_domains"
            fi
	    done < "$target_sub_domains"
    fi
    
    sort -u "$target_redirect_domains" -o "$target_redirect_domains"
    
    awk -F[/:] '{print $4}' "$target_redirect_domains" | sort -u >> "$target_redirect_for_scope_domains"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    echo -e "${GREEN}[+]${NC} $total_redirect_domains redirected subdomains saved to $target_redirect_domains"

    total_redirect_domains_for_scope=$(wc -l < "$target_redirect_for_scope_domains")
    echo -e "${GREEN}[+]${NC} $total_redirect_domains_for_scope redirected subdomains saved to to check in scope in $target_redirect_for_scope_domains"
}

import_in_burp() {
    if ! curl -s --head --request GET "$proxy_url" | grep "200 OK" > /dev/null; then
        echo -e "${RED}[!]${NC} Warning: Burp Suite proxy at $proxy_url is not reachable."
        return 1
    fi

    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Sending reachable domains to Burp Suite Proxy using curl..."

    total_live_domains=$(wc -l < "$target_live_domains")
    count=0

    for live_domain in $(cat "$target_live_domains"); do
        ((count++))
        echo -e "${YELLOW}[+]${NC} Sending domain $count/$total_live_domains: $live_domain"
        curl -s -x "$proxy_url" -k "$live_domain" -H "$HEADER" > /dev/null
    done

    echo -e "${GREEN}[+]${NC} $count domains were successfully sent to the proxy."
}

take_screenshots() {    
    total_life_domains=$(wc -l < "$target_live_domains")
    
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of ${total_life_domains} live domains with gowitness..."
    gowitness scan file -f "$target_live_domains" -s "$screenshots"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of ${total_redirect_domains} redirect domains with gowitness..."
    gowitness scan file -f "$target_redirect_domains" -s "$screenshots"
    
    total_files=$(ls -1 "$screenshots" | wc -l)
    echo -e "${BLUE}[i]${NC} $total_files screenshots were made."
}

generate_html_screenshots() {
	echo "<!DOCTYPE html><html>" > "$output_html_screenshots"
	echo "<head><title>Screenshots from $target</title>" >> "$output_html_screenshots"
    echo "<link rel='stylesheet' href='../../ptr/style.css'></head>" >> "$output_html_screenshots"
	echo "<body>" >> "$output_html_screenshots"
	echo "<h1>Screenshots from $target</h1><div class='flex'>" >> "$output_html_screenshots"
	
	count=0

	# Loop through all Nmap scan files in the directory
	for img in "${screenshots}"*.jpeg; do
	    if [[ -f "$img" ]]; then
            ((count++))
            echo "<a href='${img##*/}' data-lightbox='screenshot' data-title='${img##*/}' target='_blank'><img src='${img##*/}'></a>" >> "$output_html_screenshots"
        fi
	done

	echo "</div></body>" >> "$output_html_screenshots"
	echo "</html>" >> "$output_html_screenshots"
	echo -e "${GREEN}[+]${NC} $count screenshots were saved in $output_html_screenshots"
}

get_open_ports() {
    echo -e "${RED}[!]${NC} Active scan..."
    total_domains=$(cat "${in_scope_results}" | wc -l)
    echo -e "${FUCHSIA}[*]${NC} Scanning ${total_domains} domains for open ports with nmap. This can take a while..."
    
     # Loop through each live domain in the input file
    while read -r target_scope; do
        # Use a safe filename by replacing unwanted characters
        safe_target=$(echo $target_scope | tr -s '[:punct:]' '_' | tr ' ' '_')
    
        # Run Nmap scan and save output to a file named after the domain
        sudo nmap -sS -sV -O -oN "${nmap_ports}${safe_target}.txt" -vv -p- -T3 --script=default --min-rate=50 --max-rate=75 --max-retries=3 $target_scope
    done < "${in_scope_results}"
}

generate_html_open_ports() {
	echo "<!DOCTYPE html><html>" > "$output_html_open_ports"
	echo "<head><title>Nmap Scan Results from $target</title><link href='../../../ptr/style.css' rel='stylesheet'></head>" >> "$output_html_open_ports"
	echo "<body>" >> "$output_html_open_ports"
	echo "<h1>Nmap Scan Results for $target</h1>" >> "$output_html_open_ports"
	
	count=0

	for file_path in "$nmap_ports"*.txt; do
	    ((count++))
	    # Extract subdomain and IP address
	    subdomain=$(grep -m 1 "Nmap scan report for" "$file_path" | awk '{print $5}')
	    ip_address=$(grep -m 1 "Nmap scan report for" "$file_path" | awk -F '[()]' '{print $2}')

	    # Check if there are open ports
	    open_ports=$(grep -E "^[0-9]+/tcp" "$file_path")

	    # Only generate title and table if open ports are found
	    if [[ -n "$open_ports" ]]; then

		echo "<h2>$count) $subdomain ($ip_address)</h2>" >> "$output_html_open_ports"
		echo "<table border='1'>" >> "$output_html_open_ports"
		echo "<tr><th>Port</th><th>State</th><th>Service</th><th>Reason</th><th>Version</th></tr>" >> "$output_html_open_ports"

		# Add open ports to the table
		echo "$open_ports" | awk '{print "<tr><td>"$1"</td><td>"$2"</td><td>"$3"</td><td>"$4" "$5" "$6"</td><td>"$7"</td></tr>"}' >> "$output_html_open_ports"
		echo "</table><br>" >> "$output_html_open_ports"
	    fi
	done

	echo "</body>" >> "$output_html_open_ports"
	echo "</html>" >> "$output_html_open_ports"
	echo -e "${GREEN}[+]${NC} Nmap output with $count subdomains generated under $output_html_open_ports."
}

check_csp() {
    echo -e "${FUCHSIA}[*]${NC} Checking for CSP..."
    total_domains=$(wc -l < "$target_live_domains")
    count=0

    while read -r target_live; do
        ((count++))

        echo -e "${FUCHSIA}[*]${NC} Checking domain $count of ${total_domains}: $target_live"

        # Convert target to a safe filename format
        safe_target=$(echo $target_live | tr -s '[:punct:]' '_' | tr ' ' '_')

        # Check for Content Security Policy (CSP) in the headers
        has_csp=$(curl --connect-timeout 10 -s -D - $target_live -H "$HEADER" | grep -i "content-security-policy")
        if [[ -n "$has_csp" ]]; then
            csp_content=$(echo "$has_csp" | sed 's/[Cc]ontent-[Ss]ecurity-[Pp]olicy: //I')
    	    echo "$csp_content" > "${csp_has_file}/${safe_target}.txt"
        else
            echo $target_live > "${csp_no_file}/${safe_target}.txt"
        fi
    done < "${target_live_domains}"

    echo -e "${GREEN}[+]${NC} CSP check completed for all $total_domains domains."
    
    total_has_files=$(ls -1 "$csp_has_file" | wc -l)
    echo -e "${GREEN}[+]${NC} $total_has_files domains have a CSP."
    
    total_no_files=$(ls -1 "$csp_no_file" | wc -l)
    echo -e "${GREEN}[+]${NC} $total_no_files domains have no CSP."
}

validate_csp() {
	echo -e "${FUCHSIA}[*]${NC} Validating CSP..."
    total_has=$(ls -1 "$csp_has_file" | wc -l)

    > $csp_has_json

    for has_csp in "$csp_has_file"*.txt; do
        csp validate "${csp_has_file}${has_csp}" --output-format json &>> $csp_has_json
    done

    echo "<html><head><title>CSP Validation Report for $target</title></head><body>" > "$output_html_csp"
    echo "<h1>CSP Validation Report for $target</h1>" >> "$output_html_csp"

    # Read and process each JSON entry
    jq -c '.[]' "$input_file" | while read -r item; do
        directive=$(echo "$item" | jq -r '.directive')
        description=$(echo "$item" | jq -r '.description')

        # Extract the URL from the directive, if present
        url=$(echo "$directive" | grep -oP '(https?://[^\s]+)' || echo "URL not found")

        # Add the data to the HTML file with a structured layout
        echo "<h2>URL: $url</h2>" >> "$output_file"
        echo "<h3>CSP Validation of $directive</h3>" >> "$output_file"
        echo "<p><b>Directive:</b> $directive</p>" >> "$output_file"
        echo "<p><b>Description:</b> $description</p><hr>" >> "$output_file"
    done

    # Close the HTML tags
    echo "</body></html>" >> "$output_html_csp"

    echo "HTML report generated: $output_html_csp"
}

quick_host_up_check() {
    # Get IP/range vom input
    echo -e "${FUCHSIA}[*]${NC} Quick scan for hosts with nmap."
    echo -e "${YELLOW}[*]${NC} Insert IP/range: "
    read iprange
    safe_target=$(echo "$iprange" | tr -s '[:punct:]' '_' | tr ' ' '_')
    
    nmap -oN "${nmap_hosts}/${safe_target}_hosts.txt" -sn "$iprange"
}

remove_directories() {
    local directory=$1

    if [ -z "$directory" ]; then
        echo -e "${RED}[!]${NC} Error: No directory provided."
        exit 1
    fi

    if [ -d $directory ]; then
        echo -e "${RED}[!]${NC} Removing all files from ${directory}."
        rm -rf $directory
        if [ ! -d $directory ]; then
            echo -e "${GREEN}[+]${NC} Files are successfully removed."
            echo -e "${FUCHSIA}[*]${NC} making missing directory under: ${directory}."
            mkdir -p $directory
        fi 
    fi
}

# Loop to show menu after each task
while true; do
    display_banner

    echo -e "${FUCHSIA}==== Main Menu ====${NC}"
    echo "1. Subdomain Enumeration and Reconnaissance"
    echo "2. Domain Check and Scope Handling"
    echo "3. Security Tests"
    echo "4. Reporting and Import"
    echo "5. Cleanup"
    echo "x. Exit"
    read -p "Select a category: " main_option

    case $main_option in
        1)
            while true; do
                display_banner

                echo -e "${FUCHSIA}==== Subdomain Enumeration and Reconnaissance ====${NC}"
                echo "1. Get all subdomains (assetfinder, subfinder)"
                echo "2. Get Amass subdomains"
                echo "3. Get theHarvester entries"
                echo "4. Fetch WaybackURLs"
                echo "x. Back to Main Menu"
                read -p "Select an option: " subdomain_option

                case $subdomain_option in
                    1) get_subdomains ;;
                    2) get_amass_subdirectories ;;
                    3) get_theharvester_data ;;
                    4) get_wayback_urls ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        2)
            while true; do
                display_banner

                echo -e "${FUCHSIA}==== Domain Check and Scope Handling ====${NC}"
                echo "1. Handle redirects"
                echo "2. Check scopes"
                echo "3. Check for live domains (httprobe)"
                echo "x. Back to Main Menu"
                read -p "Select an option: " domain_option

                case $domain_option in
                    1) handle_redirects ;;
                    2) check_scopes ;;
                    3) check_live_domains ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        3)
            while true; do
                display_banner

                echo -e "${FUCHSIA}==== Security Tests ====${NC}"
                echo "1. Check CSP"
                echo "2. Validate CSP"
                echo "3. Check XSS with Dalfox"
                echo "x. Back to Main Menu"
                read -p "Select an option: " security_option

                case $security_option in
                    1) check_csp ;;
                    2) validate_csp ;;
                    3) check_xss ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        4)
            while true; do
                display_banner

                echo -e "${FUCHSIA}==== Reporting and Import ====${NC}"
                echo "1. Take screenshots (gowitness)"
                echo "2. Generate HTML output of screenshots"
                echo "3. Import into Burp Suite"
                echo "4. Quick host up check (IP/range nmap)"
                echo "5. Get open ports (nmap)"
                echo "6. Generate HTML output of open ports"
                echo "7. Check for downloads"
                echo "x. Back to Main Menu"
                read -p "Select an option: " reporting_option

                case $reporting_option in
                    1) take_screenshots ;;
                    2) generate_html_screenshots ;;
                    3) import_in_burp ;;
                    4) quick_host_up_check ;;
                    5) get_open_ports ;;
                    6) generate_html_open_ports ;;
                    7) check_for_downloads ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        5)
            while true; do
                display_banner

                echo -e "${FUCHSIA}==== Cleanup ====${NC}"
                echo "1. Cleanup all files"
                echo "2. Cleanup domains"
                echo "3. Cleanup downloads"
                echo "4. Cleanup nmap"
                echo "5. Cleanup screenshots"
                echo "6. Cleanup security"
                echo "7. Cleanup theHarvester"
                echo "8. Cleanup waybackURLs"
                echo "x. Back to Main Menu"
                read -p "Select an option: " cleanup_option

                case $cleanup_option in
                    1) 
                        remove_directories $target_domains
                        remove_directories $download_files
                        remove_directories $nmap
                        remove_directories $screenshots
                        remove_directories $security
                        remove_directories $the_harvester_files
                        remove_directories $waybackurls_files
                        ;;
                    2) remove_directories $target_domains ;;
                    3) remove_directories $download_files ;;
                    4) remove_directories $nmap ;;
                    5) remove_directories $screenshots ;;
                    6) remove_directories $security ;;
                    7) remove_directories $the_harvester_files ;;
                    8) remove_directories $waybackurls_files ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        x)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}[!]${NC} Invalid option."
            ;;
    esac
done
