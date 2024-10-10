#!/bin/bash

# Variables
VERSION="1.2.0"
PORT="8080"
proxy_url="http://127.0.0.1:${PORT}"

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

# Domain arguments
target="$1"
target_domains="../domains/${target}/"
target_sub_domains="${target_domains}sub_domains.txt"
target_live_domains="${target_domains}live_domains.txt"
target_redirect_domains="${target_domains}redirect_domains.txt"
target_redirect_for_scope_domains="${target_domains}redirect_for_scope_domains.txt"
screenshots="../screenshots/${target}"
csp_files="../csp/${target}/"
csp_has_file="${csp_files}has"
csp_no_file="${csp_files}no"
nmap="../nmap/${target}/"
output_dir="${nmap}ports"
output_file="${output_dir}/open_ports.html"

# Scope files
in_scope="../files/${target}/in_scope.txt"
out_of_scope="../files/${target}/out_of_scope.txt"

# Create files to save results
in_scope_results="${target_domains}in_scope_subdomains.txt"
out_of_scope_results="${target_domains}out_of_scope_subdomains.txt"
no_data_results="${target_domains}no_data_subdomains.txt"

# Make directories
mkdir -p "$target_domains"
mkdir -p "${nmap}/ports/"
mkdir -p "${nmap}/hosts/"
mkdir -p "$csp_has_file/"
mkdir -p "$csp_no_file/"

# Display banner
display_banner() {
    echo -e "${FUCHSIA}"
    echo "============================================"
    echo ""
    echo "             PenTestRecon"
    echo "            Version $VERSION"
    echo "      Created by SirOcram aka 0xFF00FF"
    echo -e "       For domain: ${YELLOW}$target${NC}"
    echo -e "${FUCHSIA}"
    echo "============================================"
    echo -e "${NC}"
}

# Function: Get all subdomains
get_subdomains() {
    remove_domains
    
    # Assetfinder
    if ! command -v assetfinder &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: assetfinder is not installed. Please install it first."
        return 1
    fi
    
    > "${target_sub_domains}"
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with assetfinder for ${YELLOW}$target${NC}..."
    assetfinder --subs-only "$target" | sort -u >> "${target_sub_domains}"
    
    # Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: subfinder is not installed. Please install it first."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with subfinder for ${YELLOW}$target${NC}..."
    subfinder -d "$target" -all -active -timeout 10 -silent | sort -u >> "${target_sub_domains}"
    
    total_domains=$(wc -l < "$target_sub_domains")
    echo -e "${GREEN}[+]${NC} $total_domains subdomains saved to $target_sub_domains"
}

# Amass subdirectoryfinder
get_amass_subdirectories() {
    if ! command -v amass &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: amass is not installed. Please install it first."
        return 1
    fi
    
    echo -e "${BLUE}[i]${NC} Amass is skipping for now do to issues..."
    #echo -e "${BLUE}[i]${NC} Passive scan..."
    #echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with amass for ${YELLOW}$target${NC}..."
    # Amass is crashing my machine
    #run_amass
    
    # Extrahiere Subdomains und prüfe die IPs
    #echo -e "${FUCHSIA}[*]${NC} Getting subdomains from ${target_domains}sub_domains.txt"
    #while IFS= read -r subdomain; do
    #    # Hole die IP-Adresse der Subdomain
    #    subdomain_ip=$(dig +short "$subdomain")
    #
    #    if [[ -n "$subdomain_ip" ]]; then
    #        # Überprüfe, ob die IP-Adresse in scope ist
    #        if check_ip_in_scope "$subdomain_ip"; then
    #            echo "$subdomain" >> "${target_domains}sub_domains.txt"
    #        fi
    #    fi
    #done < "${target_domains}sub_domains.txt"
    
    #echo -e "${GREEN}[+]${NC} Subdomains gathered and sorted in ${target_domains}sub_domains.txt."
}

# Function which runns amass and its scripts
run_amass() {
    amass enum -passive -o "${target_domains}amass.txt" -d "$target"
    
    # Cleaning up ANSI codes
    text=$(cat "${target_domains}amass.txt")
    clean_txt=$(remove_ansi_codes "$text")
    echo "$clean_txt" > "${target_domains}amass.txt"
    echo -e "${GREEN}[+]${NC} Clean text saved to ${target_domains}amass.txt"
    
    # Extract only IP addresses from Netblock entries and save to the cleaned file
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "${target_domains}amass_raw.txt" > "${target_domains}amass_cleaned.txt"

	# Extract only netblocks from ASN announces entries and append to the cleaned file
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "${target_domains}amass_raw.txt" >> "${target_domains}amass_cleaned.txt"

	# Remove duplicates and sort the cleaned file
	sort -u "${target_domains}amass_cleaned.txt" -o "${target_domains}amass_cleaned.txt"

    
    sort -u "${target_domains}amass_cleaned.txt" -o "${target_domains}amass.txt"

    # Sortiere die Ergebnisse
    sort -u "${target_domains}amass_subdomains.txt" -o "${target_domains}amass_subdomains.txt"
    
    echo -e "${GREEN}[+]${NC} Subdomains gathered and sorted in ${target_domains}amass_subdomains.txt."
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

    total_domains=$(wc -l < "$in_scope_results")
    count=0
    
    > "$target_live_domains" # Clear live domains file
    
    if [[ $total_domains -gt 0 ]]; then
    	# Loop through each subdomain in the combined scope
	while read -r subdomain; do
	    count=$((count + 1))
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

# Function: Handle Redirects
handle_redirects() {
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${GREEN}[+]${NC} Handle redirects with curl and save subdomains to $target_redirect_domains"
    total_domains=$(wc -l < "$target_sub_domains")
    count=0
    
    > "$target_redirect_domains" > "$target_redirect_for_scope_domains"
    
    if [[ $total_domains -gt 0 ]]; then
	    while read -r url; do
		count=$((count + 1))
		
		# Use curl to follow redirects and get the final URL
		final_url=$(curl --connect-timeout 10 -s -o /dev/null -w "%{url_effective}" -k -L "$url")
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
	    done < "$target_sub_domains"
    fi
    
    sort -u "$target_redirect_domains" -o "$target_redirect_domains"
    
    awk -F[/:] '{print $4}' "$target_redirect_domains" | sort -u >> "$target_redirect_for_scope_domains"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    printf "\r\n"
    echo -e "${GREEN}[+]${NC} $total_redirect_domains live subdomains saved to $target_redirect_domains"
}

# Function: Import in Burp
import_in_burp() {
    if ! curl -s --head --request GET "$proxy_url" | grep "200 OK" > /dev/null; then
        echo -e "${RED}[!]${NC} Warning: Burp Suite proxy at $proxy_url is not reachable."
        return 1
    fi
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${FUCHSIA}[*]${NC} Sending reachable domains to Burp Suite Proxy using curl..."

    combined_domains=$(cat "$target_live_domains" | sort -u)
    total_live_domains=$(wc -l < "$combined_domains")
    count=0

    for live_domain in $(cat "$combined_domains"); do
        count=$((count + 1))
        echo -e "${YELLOW}[+]${NC} Sending domain $count/$total_live_domains: $live_domain"
        curl -s -x "$proxy_url" -k "$live_domain" > /dev/null
    done

    echo -e "${GREEN}[+]${NC} $count domains were successfully sent to the proxy."
}

# Function: Check if subdomains are in scope
check_scopes() {
    if ! command -v grepcidr &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: grepcidr is not installed. Please install it first."
        return 1
    fi
    
    total_sub_domains=$(wc -l < "$target_redirect_for_scope_domains")
    
    echo -e "${FUCHSIA}[*]${NC} Checking $total_sub_domains subdomains for scope..."

    	# Dateien zurücksetzen, um sicherzustellen, dass sie leer sind
	> "$in_scope_results"
	> "$out_of_scope_results"
	> "$no_data_results"

	# Prüfen, ob die Scope-Dateien existieren
	if [[ ! -f "$in_scope" || ! -f "$out_of_scope" || ! -f "$target_redirect_for_scope_domains" ]]; then
	  echo "Eine oder mehrere Dateien fehlen!"
	  exit 1
	fi

	# Jede Subdomain durchgehen
	while IFS= read -r subdomain; do
	  # IP der Subdomain mit dig abrufen
	  ip=$(dig +short "$subdomain")
	  
	  # Wenn keine IP gefunden wurde, Subdomain zu no_data_results.txt hinzufügen
	  if [[ -z "$ip" ]]; then
	    echo "$subdomain" >> "$no_data_results"
	    continue
	  fi

	  # Prüfen, ob in_scope.txt leer ist
	  if [[ -s "$in_scope" ]]; then
	    # Prüfung gegen in_scope.txt
	    if echo "$ip" | grepcidr -f "$in_scope" > /dev/null; then
	      echo "$subdomain" >> "$in_scope_results"
	    else
	      echo "$subdomain" >> "$out_of_scope_results"
	    fi
	  else
	    # Wenn in_scope.txt leer ist, gegen out_of_scope.txt prüfen
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


# Function: Take screenshots
take_screenshots() {
    if ! command -v gowitness &> /dev/null; then
        echo -e "${RED}[!]${NC} Error: gowitness is not installed. Please install it first."
        return 1
    fi
    
    remove_screenshots
    
    total_life_domains=$(wc -l < "$target_live_domains")
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of ${total_life_domains} live domains with gowitness..."
    gowitness scan file -f "$target_live_domains" -s "$screenshots"
    
    total_redirect_domains=$(wc -l < "$target_redirect_domains")
    
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Taking screenshots of ${total_redirect_domains} redirect domains with gowitness..."
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
    

    total_domains=$(cat "${in_scope_results}" | wc -l)
    echo -e "${FUCHSIA}[*]${NC} Scanning ${total_domains} domains for open ports with nmap. This can take a while..."
    
     # Loop through each live domain in the input file
    while read -r target; do
        # Use a safe filename by replacing unwanted characters
        safe_target=$(echo "$target" | tr -s '[:punct:]' '_' | tr ' ' '_')
    
        # Run Nmap scan and save output to a file named after the domain
        sudo nmap -sS -sV -O -oN "${nmap}/ports/${safe_target}_open_ports.txt" -vv -p- -T3 --script=default --min-rate=50 --max-retries=3 "$target"
    done < "${in_scope_results}"
}


# Function to generate html output from open ports
generate_html_open_ports() {
	# HTML document header
	echo "<!DOCTYPE html><html>" > "$output_file"
	echo "<head><title>Nmap Scan Results for ${target}</title><link href='../../../ptr/style.css' rel='stylesheet'></head>" >> "$output_file"
	echo "<body>" >> "$output_file"
	echo "<h1>Nmap Scan Results for ${target}</h1>" >> "$output_file"
	
	count=0

	# Loop through all Nmap scan files in the directory
	for file_path in "$output_dir"/*.txt; do
	    count=$((count + 1))
	    # Extract subdomain and IP address
	    subdomain=$(grep -m 1 "Nmap scan report for" "$file_path" | awk '{print $5}')
	    ip_address=$(grep -m 1 "Nmap scan report for" "$file_path" | awk -F '[()]' '{print $2}')

	    # Check if there are open ports
	    open_ports=$(grep -E "^[0-9]+/tcp" "$file_path")

	    # Only generate title and table if open ports are found
	    if [[ -n "$open_ports" ]]; then
		# Start the table for this scan
		echo "<h2>$count) $subdomain ($ip_address)</h2>" >> "$output_file"
		echo "<table border='1'>" >> "$output_file"
		echo "<tr><th>Port</th><th>State</th><th>Service</th><th>Reason</th><th>Version</th></tr>" >> "$output_file"

		# Add open ports to the table
		echo "$open_ports" | awk '{print "<tr><td>"$1"</td><td>"$2"</td><td>"$3"</td><td>"$4" "$5" "$6"</td><td>"$7"</td></tr>"}' >> "$output_file"

		# End the table
		echo "</table><br>" >> "$output_file"
	    fi
	done

	# HTML document end
	echo "</body>" >> "$output_file"
	echo "</html>" >> "$output_file"
	echo -e "${GREEN}[+]${NC} Nmap output with $count subdomains generated under $output_file."
}

# Function to get CSP
check_csp() {
    echo -e "${FUCHSIA}[*]${NC} Checking for CSP..."
    
    remove_csp

    # Calculate the total number of domains to check
    total_domains=$(wc -l < "$target_live_domains")
    count=0

    # Loop through the sorted list of domains and check for CSP
    while read -r target; do
        ((count++))  # Increment the counter

        # Display progress
        echo -e "${FUCHSIA}[*]${NC} Checking domain $count of ${total_domains}: $target"

        # Convert target to a safe filename format
        safe_target=$(echo "$target" | tr -s '[:punct:]' '_' | tr ' ' '_')

        # Check for Content Security Policy (CSP) in the headers
        has_csp=$(curl --connect-timeout 10 -s -D - "$target" | grep -i "content-security-policy")
        if [[ -n "$has_csp" ]]; then
            echo "$has_csp" > "${csp_has_file}/${safe_target}.txt"
        else
            echo "$target" > "${csp_no_file}/${safe_target}.txt"
        fi
    done < "${target_live_domains}"

    echo -e "${GREEN}[+]${NC} CSP check completed for all $total_domains domains."
    
    total_has_files=$(ls -1 "$csp_has_file" | wc -l)
    echo -e "${GREEN}[+]${NC} $total_has_files domains have a CSP."
    
    total_no_files=$(ls -1 "$csp_no_file" | wc -l)
    echo -e "${GREEN}[+]${NC} $total_no_files domains have no CSP."
}

# Function for quick machine scan
quick_host_up_check() {
    # Get IP/range
    echo -e "${FUCHSIA}[*]${NC} Quick scan for hosts with nmap."
    echo -e "${YELLOW}[*]${NC} Insert IP/range: "
    read iprange
    safe_target=$(echo "$iprange" | tr -s '[:punct:]' '_' | tr ' ' '_')
    
    nmap -oN "${nmap}/hosts/${safe_target}_hosts.txt" -sn "$iprange"
}

# Function to clean up files
remove_domains() {
    echo -e "${RED}[!]${NC} Removing all domains from ${target_domains}."
    rm -rf $target_domains
    if [ ! -d $target_domains ]; then
    	echo -e "${GREEN}[+]${NC} Domains are successfully removed."
    	echo -e "${FUCHSIA}[*]${NC} making missing domains directory under: ${target_domains}."
	mkdir -p $target_domains
    fi
}

# Function remove screenshots
remove_screenshots() {
    echo -e "${RED}[!]${NC} Removing all screenshots from ${screenshots}."
    rm -rf $screenshots
    if [ ! -d $screenshots ]; then
    	echo -e "${GREEN}[+]${NC} Screenshots are successfully removed."
    	echo -e "${FUCHSIA}[*]${NC} making missing screenshots directory under: ${screenshots}."
	mkdir -p $screenshots
    fi
}

# Function remove open ports
remove_open_ports() {
    echo -e "${RED}[!]${NC} Removing all open ports from ${nmap}."
    rm -rf $nmap
    if [ ! -d $nmap ]; then
    	echo -e "${GREEN}[+]${NC} Open ports are successfully removed."
    	echo -e "${FUCHSIA}[*]${NC} making missing nmap directory under: ${nmap}."
	mkdir -p $nmap
    fi
}

remove_csp() {
   echo -e "${RED}[!]${NC} Removing all csp files ${csp_files}."
    rm -rf $csp_files
    if [ ! -d $csp_files ]; then
    	echo -e "${GREEN}[+]${NC} CSP files are successfully removed."
    	echo -e "${FUCHSIA}[*]${NC} making missing CSP directories under: ${csp_files}."
	mkdir -p $csp_files
	mkdir -p "$csp_has_file/"
	mkdir -p "$csp_no_file/"
    fi
}

# Loop to show menu after each task
while true; do
    display_banner
    # Menu
    echo "a. Run all"
    echo "1. Get all subdomains (assetfinder, subfinder)"
    echo "2. Get amass subdomains (skipping...)"
    echo "3. Handle redirects"
    echo "4. Check scopes"
    echo "5. Check for live domains (httprobe)"
    echo "6. Check CSP"
    echo "7. Take screenshots (gowitness)"
    echo "8. Import in Burp (burp/proxy)"
    echo "9. Quick host up check (IP/range nmap)"
    echo "10. Get open ports (nmap)"
    echo "11. Generate HTML output of open ports"
    echo "12. Cleanup all files (domains/screenshots/nmap/csp)"
    echo "13. Cleanup domains"
    echo "14. Cleanup screenshots"
    echo "15. Cleanup nmap scans"
    echo "16.Cleanup CSP files"
    echo "x. Exit"
    read -p "Select an option: " option

    # Execute based on user selection
    case $option in
        a)
            remove_domains
            remove_screenshots
            remove_open_ports
            remove_csp
            get_subdomains
            get_amass_subdirectories
            handle_redirects
            check_scopes
            check_live_domains
            check_csp
            take_screenshots
            import_in_burp
            get_open_ports
            generate_html_open_ports
            ;;
        1)
            get_subdomains
            ;;
        2)
            get_amass_subdirectories
            ;;
        3)
            handle_redirects
            ;;
        4)
            check_scopes
            ;;
        5)
            check_live_domains
            ;;
        6)
            check_csp
            ;;
        7)
            take_screenshots
            ;;
        8)
            import_in_burp
            ;;
        9)
            quick_host_up_check
            ;;
        10)
            get_open_ports
            ;;
        11)
            generate_html_open_ports
            ;;
        12)
            remove_domains
            remove_screenshots
            remove_open_ports
            remove_csp
            ;;
        13)
            remove_domains
            ;;
        14)
            remove_screenshots
            ;;
        15)
            remove_open_ports
            ;;
        16)
            remove_csp
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
