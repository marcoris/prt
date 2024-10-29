#!/bin/bash

# Read variables from .env
source .env

# Variables
VERSION="1.0.0"
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
    csp
    dalfox
    dig
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

dalfox_payloads_list=(
    portswigger
    payloadbox
)

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
target_domains="../${WEBAPP_DIR}/${target}/domains/"
target_sub_domains="${target_domains}sub_domains.txt"
target_live_domains="${target_domains}live_domains.txt"
target_redirect_domains="${target_domains}redirect_domains.txt"
target_redirect_for_scope_domains="${target_domains}redirect_for_scope_domains.txt"
in_scope_results="${target_domains}in_scope_subdomains.txt"
out_of_scope_results="${target_domains}out_of_scope_subdomains.txt"
no_data_results="${target_domains}no_data_subdomains.txt"

# Directory/file arguments
the_harvester_files="../${WEBAPP_DIR}/$target/theharvester/"
target_theharvester="${the_harvester_files}theHarvester.json"
download_files="../${WEBAPP_DIR}/$target/downloads/"
waybackurls_files="../${WEBAPP_DIR}/$target/waybackurls/"
screenshots="../${WEBAPP_DIR}/$target/screenshots/"
security="../${WEBAPP_DIR}/$target/security/"
xss_files="${security}xss/"
csp_files="${security}csp/"
xss_vulns="${xss_files}vulnerabilities.txt"
csp_has_file="${csp_files}has/"
csp_no_file="${csp_files}no/"
nmap="../${WEBAPP_DIR}/$target/nmap/"
nmap_ports="${nmap}ports/"
nmap_hosts="${nmap}hosts/"
output_html_open_ports="${nmap}open-ports-report.html"
output_html_hosts_up="${nmap}hosts-up-report.html"
output_html_screenshots="${screenshots}screenshots.html"
output_html_csp="${security}csp-report.html"
output_html_xss="${security}xss-report.html"

CSS="<link rel='stylesheet' href='../../../prt/style.css'>"

# Scope files
in_scope="../${WEBAPP_DIR}/$target/in_scope.txt"
out_of_scope="../${WEBAPP_DIR}/$target/out_of_scope.txt"

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
mkdir -p $xss_files
mkdir -p $csp_files

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

get_theharvester_data() {
    echo -e "${BLUE}[i]${NC} Passive scan..."
	limit=500
	echo -e "${FUCHSIA}[*]${NC} Fetching subdomains with theHarvester..."
    start=$(date +%s)
	theHarvester -d $target -b all -l "$limit" -n -f theharvester
	end=$(date +%s)

    email_count=$(jq -r '.emails[] | select(. != null)' theharvester.json | wc -l)
	subdomain_count=$(jq -r '.hosts[] | select(. != null)' theharvester.json | wc -l)
    interesting_urls_count=$(jq -r '.interesting_urls[] | select(. != null)' theharvester.json | wc -l)
    ip_count=$(jq -r '.ips[] | select(. != null)' theharvester.json | wc -l)
    
    echo -e "${BLUE}[i]${NC} Took ${YELLOW}$(($end-$start)) seconds${NC} to fetch theharvester data."
    echo -e "${GREEN}[+]${NC} ${YELLOW}$email_count${NC} E-Mails fetched."
	echo -e "${GREEN}[+]${NC} ${YELLOW}$subdomain_count${NC} Subdomains fetched."
    echo -e "${GREEN}[+]${NC} ${YELLOW}$interesting_urls_count${NC} Interesting URLs fetched."
    echo -e "${GREEN}[+]${NC} ${YELLOW}$ip_count${NC} IPs fetched."
        
    while true; do
        echo -e "${YELLOW}[?]${NC} Would you like to handle the data? (Y/n)"
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

    total_emails=$(wc -l < "${the_harvester_files}emails.txt")
    echo -e "${BLUE}[i]${NC} ${YELLOW}$total_emails${NC} E-mails are saved in ${YELLOW}${the_harvester_files}emails.txt${NC}"
	
    total_domains_before=$(wc -l < $target_sub_domains)

	cat "${the_harvester_files}sub_domains.txt" >> $target_sub_domains

    sort -u $target_sub_domains -o $target_sub_domains
	
    total_domains_after=$(wc -l < $target_sub_domains)
    echo -e "${BLUE}[i]${NC} ${YELLOW}$total_domains_before${NC} Subdomains before and ${YELLOW}$total_domains_after${NC} subdomains after are saved in ${YELLOW}$target_sub_domains${NC}"

    total_interesting_urls=$(wc -l < "${the_harvester_files}interesting_urls.txt")
    echo -e "${BLUE}[i]${NC} ${YELLOW}$total_interesting_urls${NC} Interesting URLs are saved in ${YELLOW}${the_harvester_files}interesting_urls.txt${NC}"

    total_ips=$(wc -l < "${the_harvester_files}ips.txt")
    echo -e "${BLUE}[i]${NC} ${YELLOW}$total_ips${NC} IPs are saved in ${YELLOW}${the_harvester_files}ips.txt${NC}"
}

get_wayback_urls() {
    echo -e "${BLUE}[i]${NC} Passive scan..."
    
    while true; do
        echo -e "${YELLOW}[?]${NC} How many years back should I scan for the domain? (default is 3):"
        read -r answer

        # Use default value 3 if no input is provided
        answer=${answer:-3}

        if [[ "$answer" =~ ^[0-9]+$ ]]; then
            get_last_years=$answer
            break
        else
            echo -e "${RED}[!]${NC} Invalid input. Please enter a number."
        fi
    done

    > "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt"

    start=$(date +%s)
	echo -e "${FUCHSIA}[*]${NC} Subdomains to fetch with WaybackURLs. This can take a while..."
	echo $target | waybackurls -dates | sort -u > "${waybackurls_files}waybackurls_raw.txt"
    
    end=$(date +%s)
	total_domains=$(wc -l < "${waybackurls_files}waybackurls_raw.txt")
    start_date=$(head -1 "${waybackurls_files}waybackurls_raw.txt" | awk '{print $1}')
    end_date=$(tail -1 "${waybackurls_files}waybackurls_raw.txt"| awk '{print $1}')
	
    echo -e "${BLUE}[i]${NC} Took ${YELLOW}$(($end-$start)) seconds${NC} to fetch ${YELLOW}$total_domains domains${NC} which are saved in ${YELLOW}${waybackurls_files}waybackurls_raw.txt${NC}"
	echo -e "${BLUE}[i]${NC} From starting date ${YELLOW}$start_date${NC} till end date ${YELLOW}$end_date${NC}"
    echo -e "${FUCHSIA}[*]${NC} Saving data since ${YELLOW}$get_last_years${NC} years ago..."

    current_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    x_years_ago=$(date -u -d "$current_date - $get_last_years years" +"%Y-%m-%dT%H:%M:%SZ")

    mapfile -t lines < "${waybackurls_files}waybackurls_raw.txt"
    start_index=$(binary_search "$x_years_ago")
    for (( i=start_index; i<${#lines[@]}; i++ )); do
        echo "${lines[$i]}" >> "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt"
    done

    cat "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt" | awk '{print $2}' | sort -u > "${waybackurls_files}waybackurls.txt"

    keywords=()

    while true; do
        read -p "Enter keyword to search (or press Enter to exit): " keyword
        if [[ -z "$keyword" ]]; then
            echo "No keyword entered. Exiting."
            break
        fi
        keywords+=("$keyword")
    done

    for keyword in "${keywords[@]}"; do
        output_file="${waybackurls_files}${keyword}.txt"
        grep -i "$keyword" "${waybackurls_files}waybackurls.txt" > "${output_file}"
        total_domains=$(wc -l < "${output_file}")
        echo -e "${BLUE}[i]${NC} ${YELLOW}$total_domains${NC} domains with keyword ${YELLOW}$keyword${NC} saved in ${YELLOW}$output_file${NC}"
    done

    total_domains_before=$(wc -l < $target_sub_domains)

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
    echo -e "${BLUE}[i]${NC} ${YELLOW}$total_domains_before${NC} Subdomains before and ${YELLOW}$total_domains_after${NC} subdomains after are saved in ${YELLOW}$target_sub_domains${NC}"
}

check_for_downloads() {
    if [ ! -n "$get_last_years" ]; then
        echo -e "${RED}[!]${NC} You first have to run the waybackurls menu entry: ${YELLOW}1.3${NC}"
        exit 1
    fi

    total_wayback_domains=$(wc -l < "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt")
    echo -e "${RED}[!]${NC} Active scan with ${YELLOW}$DELAY milliseconds${NC} delay..."
    echo -e "${FUCHSIA}[*]${NC} Checking for ${YELLOW}$total_wayback_domains${NC} downloadable files from the last ${YELLOW}$get_last_years${NC} years..."

    while IFS= read -r url; do
        if is_downloadable "$url"; then
            filename=$(basename "$url")
            filepath=$(echo "$url" | sed -E 's|https?://[^/]+/||; s|/[^/]*$||')
            mkdir -p "${download_files}${filepath}"
            echo -e "${FUCHSIA}[*]${NC} Downloading ${YELLOW}$url${NC}"
            curl -sS --connect-timeout 10 -H "User-Agent: $HEADER" -o "${download_files}${filepath}/$filename" "$url"
        fi

        sleep $(awk "BEGIN {printf \"%.2f\", $DELAY/1000}")
    done < "${waybackurls_files}waybackurls_last_${get_last_years}_years.txt"

    total_download_dirs=$(ls -1 "$download_files" | wc -l)
    total_downloaded_files=$(find "$download_files" -type f | wc -l)
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_downloaded_files${NC} files were downloaded in ${YELLOW}$total_download_dirs${NC} directories to ${YELLOW}$download_files${NC}"
}

is_downloadable() {
    local url=$1
    local content_type=$(curl -H "User-Agent: $HEADER" -sI "$url" | grep -i "Content-Type:" | cut -d' ' -f2 | tr -d '\r')

    if [ -n "$content_type" ]; then
        for type in "${allowed_types[@]}"; do
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
	    
	echo -e "${FUCHSIA}[*]${NC} Checking ${YELLOW}$total_sub_domains${NC} subdomains for scope..."

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
                if [[ -s "$out_of_scope" ]] && echo "$ip" | grepcidr -f "$out_of_scope" > /dev/null; then
                    echo "$subdomain" >> "$out_of_scope_results"
                else
                    echo "$subdomain" >> "$in_scope_results"
                fi
            fi
        else
            if [[ -s "$out_of_scope" ]] && echo "$ip" | grepcidr -f "$out_of_scope" > /dev/null; then
                echo "$subdomain" >> "$out_of_scope_results"
            else
                echo "$subdomain" >> "$in_scope_results"
            fi
        fi
	done < "$target_redirect_for_scope_domains"
    
	total_in_scope_domains=$(wc -l < "$in_scope_results")
	total_out_scope_domains=$(wc -l < "$out_of_scope_results")
	total_no_data_domains=$(wc -l < "$no_data_results")

	echo -e "${GREEN}[+]${NC} ${YELLOW}$total_in_scope_domains${NC} Subdomains are in scope."
	echo -e "${GREEN}[+]${NC} ${YELLOW}$total_out_scope_domains${NC} Subdomains are not in scope."
	echo -e "${GREEN}[+]${NC} ${YELLOW}$total_no_data_domains${NC} Subdomains are not callable."
}

check_xss() {
    if [ ! -d $xss_files ]; then
        echo -e "${FUCHSIA}[*]${NC} making missing directory under: ${xss_files}."
        mkdir -p $xss_files
    fi

    total_live_domains=$(wc -l < "$target_live_domains")

    IFS=","
    payloads="${dalfox_payloads_list[*]}"

	echo -e "${RED}[!]${NC} Active scanning for ${YELLOW}$total_live_domains live domains${NC} with ${YELLOW}dalfox${NC} for XSS vulnerabilities with a delay of ${YELLOW}$DELAY ms${NC}..."
    echo -e "${BLUE}[i]${NC} Using ${YELLOW}${payloads}${NC} as remote payloads."

    > $xss_vulns
    
    start=$(date +%s)
    cat "$target_live_domains" | dalfox pipe --config dalfox.config.json --silence --delay "$DELAY" --output $xss_vulns --remote-payloads "$payloads"
    end=$(date +%s)

    echo -e "${BLUE}[i]${NC} Took ${YELLOW}$(($end-$start)) seconds${NC} to scan for XSS vulns which are saved in ${YELLOW}$xss_vulns${NC}"
}

generate_html_xss() {
    total_xss=$(wc -l < "$xss_vulns")
	echo -e "${FUCHSIA}[*]${NC} Generating XSS report of ${YELLOW}$total_xss${NC} entries..."

    > $output_html_xss

    echo "<html>" > "$output_html_xss"
    echo "<head><title>XSS scan report for $target</title></head>" >> "$output_html_xss"
    echo "<body><h1>XSS scan report for $target</h1>" >> "$output_html_xss"

    while IFS= read -r line; do
        url=$(echo "$line" | grep -oP '(http|https)://[^\s]+')

        if [[ -n "$url" ]]; then
            echo "<p><a href=\"$url\" target=\"_blank\">$url</a></p>" >> "$output_html_xss"
        fi
    done < "$xss_vulns"

    echo "</body></html>" >> "$output_html_xss"
}

check_live_domains() {
    total_domains=$(wc -l < "$in_scope_results")
    count=0

    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Checking ${YELLOW}$total_domains${NC} reachable and in scope subdomains with httprobe..."
    
    > $target_live_domains
    
    if [[ $total_domains -gt 0 ]]; then
        while read -r subdomain; do
            ((count++))
            echo -e "${FUCHSIA}[*]${NC} Testing domain ${YELLOW}$count/$total_domains${NC}: ${YELLOW}$subdomain${NC}"
            echo "$subdomain" | httprobe >> "$target_live_domains"

            sleep $(awk "BEGIN {printf \"%.2f\", $DELAY/1000}")
        done < "$in_scope_results"
    fi
    
    total_live_domains=$(wc -l < "$target_live_domains")
    
    printf "\r\n"
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_live_domains${NC} live subdomains saved to ${YELLOW}$target_live_domains${NC}"
}

handle_redirects() {
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Handle redirects with ${YELLOW}curl${NC} and save subdomains to ${YELLOW}$target_redirect_domains${NC}"
    total_domains=$(wc -l < "$target_sub_domains")
    count=0
    
    > "$target_redirect_domains"
    > "$target_redirect_for_scope_domains"

    cat "${the_harvester_files}interesting_urls.txt" >> $target_redirect_domains
    
    if [[ $total_domains -gt 0 ]]; then
	    while read -r url; do
            ((count++))
            
            final_url=$(curl -H "User-Agent: $HEADER" --connect-timeout 10 -s -o /dev/null -w "%{url_effective}" -k -L "$url")
            # Remove the :443 port if it exists
            final_url=$(echo "$final_url" | sed 's/:443//')
            # Remove trailing slash if it exists
            final_url=$(echo "$final_url" | sed 's/\/\+$//')
            
            echo -e "${FUCHSIA}[*]${NC} Testing domain ${YELLOW}$count/$total_domains${NC}: ${YELLOW}$url${NC}"

            # Check if there is a new URL after the redirect
            if [ "$final_url" != "$url" ]; then            
                # Save the final URL with its original protocol to the live domains file
                echo "$final_url" >> "$target_redirect_domains"
            else
                # If no redirect, save the original URL
                echo "$url" >> "$target_redirect_domains"
            fi

            sleep $(awk "BEGIN {printf \"%.2f\", $DELAY/1000}")
	    done < "$target_sub_domains"
    fi
    
    sort -u "$target_redirect_domains" -o "$target_redirect_domains"
    
    awk -F[/:] '{print $4}' "$target_redirect_domains" | sort -u >> "$target_redirect_for_scope_domains"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_redirect_domains${NC} redirected subdomains saved to ${YELLOW}$target_redirect_domains${NC}"

    total_redirect_domains_for_scope=$(wc -l < "$target_redirect_for_scope_domains")
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_redirect_domains_for_scope${NC} redirected subdomains saved to to check in scope in ${YELLOW}$target_redirect_for_scope_domains${NC}"
}

import_in_burp() {
    if ! curl -s -H "User-Agent: $HEADER" --request GET "$PROXY_URL" | grep "200 OK" > /dev/null; then
        echo -e "${RED}[!]${NC} Warning: Burp Suite proxy at $PROXY_URL is not reachable."
        return 1
    fi

    echo -e "${BLUE}[i]${NC} Active scan..."

    total_live_domains=$(wc -l < "$target_live_domains")
    echo -e "${FUCHSIA}[*]${NC} Sending ${YELLOW}$total_live_fomains${NC} reachable domains to Burp Suite Proxy using curl..."
    count=0

    for live_domain in $(cat "$target_live_domains"); do
        ((count++))
        echo -e "${YELLOW}[+]${NC} Sending domain $count/$total_live_domains: $live_domain"
        curl -s -H "User-Agent: $HEADER" -x "$PROXY_URL" -k "$live_domain" > /dev/null

        sleep $(awk "BEGIN {printf \"%.2f\", $DELAY/1000}")
    done

    echo -e "${GREEN}[+]${NC} ${YELLOW}$count${NC} domains were successfully sent to the proxy."
}

take_screenshots() {    
    total_life_domains=$(wc -l < "$target_live_domains")
    
    start=$(date +%s)
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of ${YELLOW}$total_life_domains live domains${NC} with gowitness..."
    gowitness scan file -f "$target_live_domains" -s "$screenshots"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of ${YELLOW}$total_redirect_domains redirect domains${NC} with gowitness..."
    gowitness scan file -f "$target_redirect_domains" -s "$screenshots"
    end=$(date +%s)

    total_files=$(ls -1 "$screenshots" | wc -l)
    echo -e "${BLUE}[i]${NC} Took ${YELLOW}$(($end-$start)) seconds${NC} to shoot ${YELLOW}$total_files${NC} screenshots."
}

generate_html_screenshots() {
	echo "<!DOCTYPE html><html>" > "$output_html_screenshots"
	echo "<head><title>Screenshots from $target</title>" >> "$output_html_screenshots"
    echo "${CSS}</head>" >> "$output_html_screenshots"
	echo "<body>" >> "$output_html_screenshots"
	echo "<h1>Screenshots from $target</h1><div class='flex'>" >> "$output_html_screenshots"
	
	count=0

	# Loop through all Nmap scan files in the directory
	for img in "${screenshots}"*.jpeg; do
	    if [[ -f "$img" ]]; then
            ((count++))
            echo "<a href='${img##*/}' target='_blank'><img src='${img##*/}'></a>" >> "$output_html_screenshots"
        fi
	done

	echo "</div></body></html>" >> "$output_html_screenshots"
	echo -e "${GREEN}[+]${NC} ${YELLOW}$count${NC} screenshots were saved in ${YELLOW}$output_html_screenshots${NC}"
}

get_open_ports() {
    total_ips=$(cat "${nmap}ips.txt" | wc -l)
    echo -e "${RED}[!]${NC} Active scan of ${YELLOW}$total_ips${NC} IPs for status with nmap..."
    
    start=$(date +%s)

    while read -r ip; do
        sudo nmap -oN "${nmap_ports}${ip}.txt" "$ip" -p- -sV -O -T3 --excludefile "$out_of_scope"
    done < "${nmap}ips.txt"

    end=$(date +%s)

    diff=$(($end-$start))
    minutes=$((diff / 60))
    echo -e "${GREEN}[+]${NC} Took ${YELLOW}$minutes minutes${NC} to scan $total_ips IPs with nmap."
}

generate_html_open_ports() {
	echo "<!DOCTYPE html><html>" > "$output_html_open_ports"
	echo "<head><title>Nmap scan report for $target</title>${CSS}</head>" >> "$output_html_open_ports"
	echo "<body>" >> "$output_html_open_ports"
	echo "<h1>Nmap scan report for $target</h1>" >> "$output_html_open_ports"
	
	count=0

	for file_path in "$nmap_ports"*.txt; do
	    ((count++))
	    subdomain=$(grep -m 1 "Nmap scan report for" "$file_path" | awk '{print $5}')
	    ip_address=$(grep -m 1 "Nmap scan report for" "$file_path" | awk -F '[()]' '{print $2}')

	    open_ports=$(grep -E "^[0-9]+/tcp" "$file_path")
        os_details=$(grep -m 1 "OS details" "$file_path")

	    if [[ -n "$open_ports" ]]; then

		echo "<h2>$count) $subdomain ($ip_address)</h2>" >> "$output_html_open_ports"
		echo "<table border='1'>" >> "$output_html_open_ports"
		echo "<tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>" >> "$output_html_open_ports"

		echo "$open_ports" | awk '{print "<tr><td>"$1"</td><td>"$2"</td><td>"$3"</td><td>"$4" "$5" "$6" "$7"</td></tr>"}' >> "$output_html_open_ports"
		echo "</table><br>" >> "$output_html_open_ports"
        echo "${os_details}<br>" >> "$output_html_open_ports"
	    fi
	done

	echo "</body></html>" >> "$output_html_open_ports"
	echo -e "${GREEN}[+]${NC} Nmap scan report with ${YELLOW}$count${NC} subdomains generated under ${YELLOW}$output_html_open_ports${NC}"
}

check_csp() {
    if [ ! -d $csp_has_file ]; then
        echo -e "${FUCHSIA}[*]${NC} making missing directory under: ${csp_has_file}."
        mkdir -p $csp_has_file
    fi

    if [ ! -d $csp_no_file ]; then
        echo -e "${FUCHSIA}[*]${NC} making missing directory under: ${csp_no_file}."
        mkdir -p $csp_no_file
    fi

    echo -e "${BLUE}[i]${NC} Active scan..."
    total_domains=$(wc -l < "$target_live_domains")
    count=0

    while read -r target_live; do
        ((count++))

        echo -e "${FUCHSIA}[*]${NC} Checking domain ${YELLOW}$count/$total_domains${NC}: ${YELLOW}$target_live${NC}"

        safe_target=$(echo $target_live | tr -s '[:punct:]' '_' | tr ' ' '_')

        has_csp=$(curl -H "User-Agent: $HEADER" --connect-timeout 10 -s -D - $target_live | grep -i "content-security-policy")
        
        if [[ -n "$has_csp" ]]; then
            csp_content=$(echo "$has_csp" | sed 's/[Cc]ontent-[Ss]ecurity-[Pp]olicy: //I')
            echo "$target_live" > "${csp_has_file}/${safe_target}.txt"
    	    echo "$csp_content" >> "${csp_has_file}/${safe_target}.txt"
        else
            echo $target_live > "${csp_no_file}/${safe_target}.txt"
        fi

        sleep $(awk "BEGIN {printf \"%.2f\", $DELAY/1000}")
    done < "${target_live_domains}"
    
    total_has_files=$(ls -1 "$csp_has_file" | wc -l)
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_has_files${NC} domains have a CSP."
    
    total_no_files=$(ls -1 "$csp_no_file" | wc -l)
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_no_files${NC} domains have no CSP."
}

generate_html_csp() {
    total_has=$(ls -1 "$csp_has_file" | wc -l)
	echo -e "${FUCHSIA}[*]${NC} Generating CSP report of ${YELLOW}$total_has${NC} files..."

    > $output_html_csp

    echo "<html><head><title>CSP scan report for $target</title></head><body>" > "$output_html_csp"
    echo "<h1>CSP scan report for $target</h1>" >> "$output_html_csp"
    echo "<a href='https://csp-evaluator.withgoogle.com/' target='_blank'>CSP Evaluator</a>" >> "$output_html_csp"

    for file in "$csp_has_file"*; do
        url=$(sed -n '1p' "$file")
        csp_derivate=$(sed -n '2p' "$file")

        echo "<h2>${url}</h2>" >> "$output_html_csp"
        echo "<p>${csp_derivate}</p>" >> "$output_html_csp"
        echo "<hr>" >> "$output_html_csp"
    done

    echo "</body></html>" >> "$output_html_csp"

    echo -e "${GREEN}[+]${NC} HTML report generated under ${YELLOW}$output_html_csp${NC}"
}

quick_host_up_check() {
    total_domains=$(wc -l < "$target_live_domains")
    echo -e "${BLUE}[i]${NC} Passive scan for ${YELLOW}$total_domains${NC} hosts with ${YELLOW}ping${NC} command."

    > "${nmap}ips.txt"
    > "${nmap}iplist.txt"
    count=0

    while IFS= read -r subdomain; do
        ((count++))
        echo -e "${FUCHSIA}[*]${NC} Getting IP from domain ${YELLOW}$count/$total_domains${NC}: ${YELLOW}$subdomain${NC}"

        domain=$(echo $subdomain | sed 's~http[s]*://~~')
        iplist=$(ping -c 1 "$domain" >> "${nmap}iplist.txt")
    done < "$target_live_domains"

    grep -oP '\(\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${nmap}iplist.txt" > "${nmap}ips.txt"

    sort -u "${nmap}ips.txt" -o "${nmap}ips.txt"

    total_ips=$(wc -l < "${nmap}ips.txt")

    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_ips${NC} IPs saved to ${YELLOW}${nmap}ips.txt${NC}"

    if [ "$total_ips" -gt 0 ]; then
        echo -e "${BLUE}[i]${NC} Quick passive scan for hosts with nmap."

        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                nmap -oN "${nmap_hosts}/${ip}.txt" "$ip" --excludefile "$out_of_scope"
            fi
        done < "${nmap}ips.txt"
    fi

    total_hosts=$(ls -1 "$nmap_hosts" | wc -l)
    echo -e "${GREEN}[+]${NC} ${YELLOW}$total_hosts${NC} Hosts are up."
}

generate_html_quickhost_up() {
	echo "<!DOCTYPE html><html>" > "$output_html_hosts_up"
	echo "<head><title>Quick host up check report for $target</title>${CSS}</head>" >> "$output_html_hosts_up"
	echo "<body>" >> "$output_html_hosts_up"
	echo "<h1>Quick host up check report for $target</h1>" >> "$output_html_hosts_up"
	
	count=0

	for file_path in "$nmap_hosts"*.txt; do
	    ((count++))
	    subdomain=$(grep -m 1 "Nmap scan report for" "$file_path" | awk '{print $5}')
	    ip_address=$(grep -m 1 "Nmap scan report for" "$file_path" | awk -F '[()]' '{print $2}')

	    ports=$(grep -E "^[0-9]+/tcp" "$file_path")

	    if [[ -n "$ports" ]]; then
            echo "<h2>$count) $subdomain ($ip_address)</h2>" >> "$output_html_hosts_up"
            echo "<table border='1'>" >> "$output_html_hosts_up"
            echo "<tr><th>Port</th><th>State</th><th>Service</th></tr>" >> "$output_html_hosts_up"

            echo "$ports" | awk '{
                color = ($2 == "open") ? "green" : "red";
                print "<tr><td>"$1"</td><td><span style=\"color:" color "\">" $2 "</span></td><td>" $3 " " $4 " " $5 " " $6 "</td></tr>"
            }' >> "$output_html_hosts_up"

            echo "</table><br>" >> "$output_html_hosts_up"
	    fi
	done

	echo "</body></html>" >> "$output_html_hosts_up"
	echo -e "${GREEN}[+]${NC} Nmap scan report with ${YELLOW}$count${NC} subdomains generated under ${YELLOW}$output_html_hosts_up${NC}"
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

display_banner() {
    echo -e "${FUCHSIA}===================================================="
    echo ""
    echo "                 Pentester Recon Tool"
    echo "                     Version $VERSION"
    echo "          Created by SirOcram aka 0xFF00FF"
    echo -e "       For domain: ${YELLOW}$target${NC}"
    echo -e "${GREEN}  Header: $HEADER"
    echo ""
}

# Loop to show menu after each task
while true; do
    display_banner

    echo -e "${FUCHSIA}==================== Main Menu =====================${NC}"
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

                echo -e "${FUCHSIA}===== Subdomain Enumeration and Reconnaissance =====${NC}"
                echo "1. Get all subdomains (assetfinder, subfinder)"
                echo "2. Get theHarvester entries"
                echo "3. Get WaybackURLs"
                echo "x. Back to Main Menu"
                read -p "Select an option: " subdomain_option

                case $subdomain_option in
                    1) get_subdomains ;;
                    2) get_theharvester_data ;;
                    3) get_wayback_urls ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        2)
            while true; do
                display_banner

                echo -e "${FUCHSIA}========= Domain Check and Scope Handling ==========${NC}"
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

                echo -e "${FUCHSIA}================== Security Tests ==================${NC}"
                echo "1. Check CSP"
                echo "2. Check XSS with Dalfox"
                echo "x. Back to Main Menu"
                read -p "Select an option: " security_option

                case $security_option in
                    1) check_csp ;;
                    2) check_xss ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        4)
            while true; do
                display_banner

                echo -e "${FUCHSIA}=============== Reporting and Import ===============${NC}"
                echo "1. Generate report of CSP"
                echo "2. Generate report of XSS"
                echo "3. Take screenshots (gowitness)"
                echo "4. Generate HTML output of screenshots"
                echo "5. Import into Burp Suite"
                echo "6. Quick host up check (IP/range nmap)"
                echo "7. Generate HTML output of up hosts"
                echo "8. Get open ports (nmap)"
                echo "9. Generate report of open ports"
                echo "10. Check for downloads"
                echo "x. Back to Main Menu"
                read -p "Select an option: " reporting_option

                case $reporting_option in
                    1) generate_html_csp ;;
                    2) generate_html_xss ;;
                    3) take_screenshots ;;
                    4) generate_html_screenshots ;;
                    5) import_in_burp ;;
                    6) quick_host_up_check ;;
                    7) generate_html_quickhost_up ;;
                    8) get_open_ports ;;
                    9) generate_html_open_ports ;;
                    10) check_for_downloads ;;
                    x) break ;;
                    *) echo -e "${RED}[!]${NC} Invalid option." ;;
                esac
            done
            ;;
        5)
            while true; do
                display_banner

                echo -e "${FUCHSIA}===================== Cleanup ======================${NC}"
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
