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
    echo -e "${BLUE}[i]${NC} Passive scan..."
    echo -e "${FUCHSIA}[*]${NC} Gathering subdomains with amass for ${YELLOW}$target${NC}..."
    # Amass is crashing my machine
    #run_amass
    
    # Extrahiere Subdomains und prüfe die IPs
    echo -e "${FUCHSIA}[*]${NC} Getting subdomains from ${target_domains}sub_domains.txt"
    while IFS= read -r subdomain; do
        # Hole die IP-Adresse der Subdomain
        subdomain_ip=$(dig +short "$subdomain")

        if [[ -n "$subdomain_ip" ]]; then
            # Überprüfe, ob die IP-Adresse in scope ist
            if check_ip_in_scope "$subdomain_ip"; then
                echo "$subdomain" >> "${target_domains}sub_domains.txt"
            fi
        fi
    done < "${target_domains}sub_domains.txt"
    
    echo -e "${GREEN}[+]${NC} Subdomains gathered and sorted in ${target_domains}sub_domains.txt."
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
    
    
    # Extrahiere Subdomains und prüfe die IPs
    echo -e "${FUCHSIA}[*]${NC} Getting subdomains from ${target_domains}amass.txt"
    while IFS= read -r subdomain; do
        # Hole die IP-Adresse der Subdomain
        subdomain_ip=$(dig +short "$subdomain")

        if [[ -n "$subdomain_ip" ]]; then
            # Überprüfe, ob die IP-Adresse in scope ist
            if check_ip_in_scope "$subdomain_ip"; then
                echo "$subdomain" >> "${target_domains}amass_subdomains.txt"
            fi
        fi
    done < "${target_domains}amass.txt"

    # Sortiere die Ergebnisse
    sort -u "${target_domains}amass_subdomains.txt" -o "${target_domains}amass_subdomains.txt"
    
    echo -e "${GREEN}[+]${NC} Subdomains gathered and sorted in ${target_domains}amass_subdomains.txt."
}

# Cleanup ANSI codes function
remove_ansi_codes() {
    local input_text="$1"
    echo "$input_text" | awk '{gsub(/\x1b\[[0-9;]*[a-zA-Z]/, "")}1'
}

check_ip_in_scope() {
    local ip="$1"
    local in_scope_file="$in_scope"
    local out_of_scope_file="$out_of_scope"

    # Wenn eine Out-of-Scope-Datei vorhanden ist, prüfen wir zuerst, ob die IP out of scope ist
    if [[ -f "$out_of_scope_file" ]]; then
        if grepcidr -f "$out_of_scope_file" <<< "$ip" &> /dev/null; then
            return 1  # IP ist out of scope
        fi
    fi

    # Wenn eine In-Scope-Datei vorhanden ist, prüfen wir, ob die IP in scope ist
    if [[ -f "$in_scope_file" ]]; then
        if grepcidr -f "$in_scope_file" <<< "$ip" &> /dev/null; then
            return 0  # IP ist in scope
        else
            return 1  # IP ist nicht in scope
        fi
    fi

    # Wenn keine der Dateien vorhanden ist, gehen wir davon aus, dass die IP gültig ist
    return 0  # Keine spezifischen Angaben, daher IP als gültig betrachten
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
    
    total_domains=$(wc -l < "$out_of_scope_results")
    count=0
    
    if [[ $total_domains -gt 0 ]]; then
    	# Loop through each subdomain in the combined scope
	while read -r subdomain; do
	    count=$((count + 1))
	    percentage=$((100 * count / total_domains))
	    printf "\r                                                                                                  "
	    printf "\r${FUCHSIA}[*]${NC} Testing domain $count/$total_domains: $subdomain - Percentage: [${GREEN}%d%%${NC}]" "$percentage"
	    echo "$subdomain" | httprobe >> "$target_live_domains"
	done < "$out_of_scope_results"
    fi
    
    total_live_domains=$(wc -l < "$target_live_domains")
    
    printf "\r\n"
    echo -e "${GREEN}[+]${NC} $total_live_domains live subdomains saved to $target_live_domains"
}

# Function: Handle Redirects
handle_redirects() {
    echo -e "${BLUE}[i]${NC} Active scan..."
    echo -e "${GREEN}[+]${NC} Handle redirects with curl and save subdomains to $target_redirect_domains"
    total_domains=$(wc -l < "$in_scope_results")
    count=0
    
    > "$target_redirect_domains"
    
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
	    done < "$in_scope_results"
    fi
    
    total_domains=$(wc -l < "$out_of_scope_results")
    count=0
    
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
	    done < "$out_of_scope_results"
    fi
    
    sort -u "$target_redirect_domains" -o "$target_redirect_domains"
    
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

    combined_domains=$(cat "$target_live_domains" "$target_redirect_domains" | sort -u)
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
    local subdomain_ip
    local is_in_scope=0
    local is_out_of_scope=0

    # Make sure the scope files exist
    if [[ ! -f "$in_scope" ]]; then
        echo -e "${RED}[!]${NC} Error: $in_scope does not exist."
        return 1
    fi

    if [[ ! -f "$out_of_scope" ]]; then
        echo -e "${RED}[!]${NC} Error: $out_of_scope does not exist."
        return 1
    fi

    echo -e "${FUCHSIA}[*]${NC} Checking subdomains for scope..."

    # Check if the in_scope file is empty
    if [[ ! -s "$in_scope" ]]; then
        echo -e "${YELLOW}[i]${NC} Info: $in_scope is empty. Only checking with out_of_scope ranges."
        mapfile -t out_of_scope_ranges < "$out_of_scope"
        check_only_out_of_scope=true
    else
        mapfile -t in_scope_ranges < "$in_scope"
        mapfile -t out_of_scope_ranges < "$out_of_scope"
        check_only_out_of_scope=false
    fi

    # Empty the results files first
    > "$in_scope_results"
    > "$out_of_scope_results"
    > "$no_data_results"

    # Loop through each subdomain and check if its IP is within scope
    while read -r subdomain; do
        # Get the IP of the subdomain
        subdomain_ip=$(dig +short "$subdomain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

        if [[ -z "$subdomain_ip" ]]; then
            echo "$subdomain" >> "$no_data_results"
            continue
        fi

        is_in_scope=0
        is_out_of_scope=0

        if [[ "$check_only_out_of_scope" == false ]]; then
            # Check if the subdomain IP is in the in-scope range
            for range in "${in_scope_ranges[@]}"; do
                if ipcalc -nb "$subdomain_ip" "$range" &> /dev/null; then
                    is_in_scope=1
                    echo "$subdomain" >> "$in_scope_results"
                    break
                fi
            done
        fi

        # If not in in-scope or if in_scope.txt is empty, check if it's out-of-scope
        if [[ "$is_in_scope" -eq 0 ]]; then
            for range in "${out_of_scope_ranges[@]}"; do
                if ipcalc -nb "$subdomain_ip" "$range" &> /dev/null; then
                    is_out_of_scope=1
                    echo "$subdomain" >> "$out_of_scope_results"
                    break
                fi
            done
        fi

        # If not in any scope, add to no data
        if [[ "$is_in_scope" -eq 0 && "$is_out_of_scope" -eq 0 ]]; then
            echo "$subdomain" >> "$no_data_results"
        fi
    done < "$target_sub_domains"
    
    total_in_scope_domains=$(wc -l < "$in_scope_results")
    total_out_scope_domains=$(wc -l < "$out_of_scope_results")
    total_classified_domains=$((total_in_scope_domains + total_out_scope_domains))


    echo -e "${GREEN}[+]${NC} ${total_classified_domains} Subdomains classified into scope files."
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
    sed 's~http[s]\?://~~g' $target_live_domains > "${target_domains}cleaned_live.txt"

    cat "${target_domains}cleaned_live.txt" | sort -u > "${target_domains}nmap_domains.txt"

    total_domains=$(cat "${target_domains}nmap_domains.txt" | wc -l)
    echo -e "${FUCHSIA}[*]${NC} Scanning ${total_domains} domains for open ports with nmap. This can take a while..."
    
     # Loop through each live domain in the input file
    while read -r target; do
        # Use a safe filename by replacing unwanted characters
        safe_target=$(echo "$target" | tr -s '[:punct:]' '_' | tr ' ' '_')
    
        # Run Nmap scan and save output to a file named after the domain
        sudo nmap -sS -sV -O -oN "${nmap}/ports/${safe_target}_open_ports.txt" -vv -p- -T3 --script=default --open --min-rate=50 --max-retries=3 "$target"
    done < "${target_domains}nmap_domains.txt"
}


# Function to generate html output from open ports
generate_html_open_ports() {
	# HTML document header
	echo "<html>" > "$output_file"
	echo "<head><title>Nmap Scan Results for ${target}</title></head>" >> "$output_file"
	echo "<body>" >> "$output_file"
	echo "<h1>Nmap Scan Results for ${target}</h1>" >> "$output_file"

	# Loop through all Nmap scan files in the directory
	for file_path in "$output_dir"/*.txt; do
	    # Extract subdomain and IP address
	    subdomain=$(grep -m 1 "Nmap scan report for" "$file_path" | awk '{print $5}')
	    ip_address=$(grep -m 1 "Nmap scan report for" "$file_path" | awk -F '[()]' '{print $2}')

	    # Check if there are open ports
	    open_ports=$(grep -E "^[0-9]+/tcp" "$file_path")

	    # Only generate title and table if open ports are found
	    if [[ -n "$open_ports" ]]; then
		# Start the table for this scan
		echo "<h2>$subdomain ($ip_address)</h2>" >> "$output_file"
		echo "<table border='1'>" >> "$output_file"
		echo "<tr><th>Ports</th><th>Service</th><th>Reason</th><th>Version</th></tr>" >> "$output_file"

		# Add open ports to the table
		echo "$open_ports" | awk '{print "<tr><td>"$1"</td><td>"$2"</td><td>"$3"</td><td>"$4" "$5" "$6" "$7" "$8" "$9"</td></tr>"}' >> "$output_file"

		# End the table
		echo "</table><br>" >> "$output_file"
	    fi
	done

	# HTML document end
	echo "</body>" >> "$output_file"
	echo "</html>" >> "$output_file"
	echo -e "${GREEN}[+]${NC} Nmap output generated under $output_file."
}

# Function to get CSP
check_csp() {
    echo -e "${FUCHSIA}[*]${NC} Checking for CSP..."
    # Combine, sort, and remove duplicates from both domain lists
    combined_domains=$(cat "$target_live_domains" "$target_redirect_domains" | sort -u)

    # Calculate the total number of domains to check
    total_domains=$(echo "$combined_domains" | wc -l)
    count=0

    # Loop through the sorted list of domains and check for CSP
    while read -r target; do
        ((count++))  # Increment the counter

        # Display progress
        echo -e "${FUCHSIA}[*]${NC} Checking domain $count of $total_domains: $target"

        # Convert target to a safe filename format
        safe_target=$(echo "$target" | tr -s '[:punct:]' '_' | tr ' ' '_')

        # Check for Content Security Policy (CSP) in the headers
        has_csp=$(curl --connect-timeout 10 -s -D - "$target" | grep -i "content-security-policy")
        if [[ -n "$has_csp" ]]; then
            echo "$has_csp" > "${csp_has_file}/${safe_target}.txt"
        else
            echo "$target" > "${csp_no_file}/${safe_target}.txt"
        fi
    done <<< "$combined_domains"

    echo -e "${FUCHSIA}[*]${NC} CSP check completed for all $total_domains domains."
    
    total_has_files=$(ls -1 "$csp_has_file" | wc -l)
    echo -e "${FUCHSIA}[*]${NC} $total_has_files domains have a CSP."
    
    total_no_files=$(ls -1 "$csp_no_file" | wc -l)
    echo -e "${FUCHSIA}[*]${NC} $total_no_files domains have no CSP."
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
    fi
}

# Function remove screenshots
remove_screenshots() {
    echo -e "${RED}[!]${NC} Removing all screenshots from ${screenshots}."
    rm -rf $screenshots
    if [ ! -d $screenshots ]; then
    	echo -e "${GREEN}[+]${NC} Screenshots are successfully removed."
    fi
}

# Function remove open ports
remove_open_ports() {
    echo -e "${RED}[!]${NC} Removing all open ports from ${nmap}."
    rm -rf $nmap
    if [ ! -d $nmap ]; then
    	echo -e "${GREEN}[+]${NC} Open ports are successfully removed."
    fi
}

remove_csp() {
   echo -e "${RED}[!]${NC} Removing all csp files ${csp_files}."
    rm -rf $csp_files
    if [ ! -d $csp_files ]; then
    	echo -e "${GREEN}[+]${NC} CSP files are successfully removed."
    fi
}

# Loop to show menu after each task
while true; do
    display_banner
    # Menu
    echo "a. Run all"
    echo "1. Get all subdomains (assetfinder, subfinder)"
    echo "2. Get amass subdomains"
    echo "3. Check scopes"
    echo "4. Check for live domains (httprobe)"
    echo "5. Handle redirects"
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
            check_scopes
            check_live_domains
            handle_redirects
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
            check_scopes
            ;;
        4)
            check_live_domains
            ;;
        5)
            handle_redirects
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
