#!/bin/bash

banner() {
clear
printf "\e[0m\n"
printf "\e[1;33m  888b     d888 Y88b   d88P 888    888                   888      \e[0m\n"
printf "\e[1;33m  8888b   d8888  Y88b d88P  888    888                   888      \e[0m\n"
printf "\e[1;33m  88888b.d88888   Y88o88P   888    888                   888      \e[0m\n"
printf "\e[1;33m  888Y88888P888    Y888P    8888888888  8888b.   .d8888b 888  888 \e[0m\n"
printf "\e[1;33m  888 Y888P 888    d888b    888    888     \"88b d88P\"    888 .88P \e[0m\n"
printf "\e[1;33m  888  Y8P  888   d88888b   888    888 .d888888 888      888888K  \e[0m\n"
printf "\e[1;33m  888   \"   888  d88P Y88b  888    888 888  888 Y88b.    888 \"88b \e[0m\n"
printf "\e[1;33m  888       888 d88P   Y88b 888    888 \"Y888888  \"Y8888P 888  888 \e[0m\n"
printf "\e[0m\n"
printf "\e[1;33m    Created by vpm666\e[0m\n"
}

phone_info() {
banner
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Enter Phone Number (with country code): \e[0m\e[1;96m' phone_number

cleaned_number=$(echo "$phone_number" | tr -d '[:space:]-+()')
country_code=$(echo "$cleaned_number" | grep -oP '^\d{1,3}')

printf "\n\e[1;33mPhone Information:\e[0m\n"

api_data=$(curl -s "https://phonevalidation.abstractapi.com/v1/?api_key=TU_API_KEY&phone=$phone_number" 2>/dev/null)

if [ -z "$api_data" ]; then
    printf "\e[1;31mError: Could not connect to validation service\e[0m\n"
else
    valid=$(echo "$api_data" | grep -oP '"valid":\K[^,]+')
    country=$(echo "$api_data" | grep -oP '"country":{"name":"\K[^"]+')
    carrier=$(echo "$api_data" | grep -oP '"carrier":"\K[^"]+')
    line_type=$(echo "$api_data" | grep -oP '"type":"\K[^"]+')

    printf "\e[1;33mNumber: \e[1;92m$phone_number\e[0m\n"
    printf "\e[1;33mValid: \e[1;92m$valid\e[0m\n"
    printf "\e[1;33mCountry: \e[1;92m${country:-Unknown}\e[0m\n"
    printf "\e[1;33mCarrier: \e[1;92m${carrier:-Unknown}\e[0m\n"
    printf "\e[1;33mLine Type: \e[1;92m${line_type:-Unknown}\e[0m\n"

    if [[ "$country_code" == "52" ]]; then
        printf "\e[1;33mAdditional Info: \e[1;92mMexican number detected\e[0m\n"
    fi
fi

printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Press Enter to continue... \e[0m'
banner
menu
}

scan_ports() {
banner
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Target IP to Scan: \e[0m\e[1;96m' target_ip

if [[ -z "$target_ip" ]]; then
    printf " \e[1;91m[!] No IP entered\e[0m\n"
    sleep 2
    banner
    menu
    return
fi

printf "\n\e[1;33mStarting advanced scan on $target_ip\e[0m\n"
printf "\e[1;33m---------------------------------------\e[0m\n"

printf "\e[1;33m\nRunning comprehensive port scan...\e[0m\n"
scan_results=$(nmap -T4 -A -v -p- --script vuln,malware,auth $target_ip)

printf "\n\e[1;33mScan Results Summary:\e[0m\n"
printf "\e[1;33m---------------------------------------\e[0m\n"

host_status=$(echo "$scan_results" | grep "Host is up")
latency=$(echo "$host_status" | grep -oP 'latency of \K[^,]+')
printf "\e[1;33mHost Status: \e[1;92m${host_status:-Not responding}\e[0m\n"

open_ports=$(echo "$scan_results" | grep -oP '\d+/[^/]+/open' | wc -l)
printf "\e[1;33mOpen Ports Found: \e[1;92m$open_ports\e[0m\n"

os_info=$(echo "$scan_results" | grep -A1 "Aggressive OS guesses" | tail -1 | sed 's/|//g')
printf "\e[1;33mOS Detection: \e[1;92m${os_info:-Not identified}\e[0m\n"

vulns=$(echo "$scan_results" | grep -i "vulnerable\|CVE-" | wc -l)
printf "\e[1;33mVulnerabilities Detected: \e[1;92m$vulns\e[0m\n"

printf "\n\e[1;33mDetailed Open Ports:\e[0m\n"
echo "$scan_results" | grep "open" | while read -r line; do
    port=$(echo "$line" | cut -d'/' -f1)
    service=$(echo "$line" | cut -d'/' -f3)
    printf "\e[1;33mPort \e[1;92m$port\e[1;33m (\e[1;92m$service\e[1;33m)\e[0m\n"
done

printf "\n\e[1;33mSecurity Recommendations:\e[0m\n"
if [[ "$open_ports" -gt 0 ]]; then
    echo "$scan_results" | grep "open" | while read -r line; do
        port=$(echo "$line" | cut -d'/' -f1)
        case $port in
            22) printf "\e[1;31m- SSH detected on port 22: Consider brute force attack using hydra\e[0m\n";;
            80|443) printf "\e[1;31m- Web service detected: Run nikto or dirb for web vulnerabilities\e[0m\n";;
            139|445) printf "\e[1;31m- SMB service detected: Check for EternalBlue vulnerability\e[0m\n";;
            21) printf "\e[1;31m- FTP detected: Check for anonymous login\e[0m\n";;
            3389) printf "\e[1;31m- RDP detected: Possible brute force target\e[0m\n";;
            *) printf "\e[1;31m- Service on port $port: Research specific exploits\e[0m\n";;
        esac
    done
else
    printf "\e[1;31m- All ports filtered: Consider ARP spoofing or other network-level attacks\e[0m\n"
fi

printf "\n\e[1;33mFull scan results saved to scan_$target_ip.txt\e[0m\n"
echo "$scan_results" > "scan_$target_ip.txt"

printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Press Enter to continue... \e[0m'
banner
menu
}

generate_report() {
clear
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Enter IP Address: \e[0m' reportip

ipdata=$(curl -s "https://ipapi.co/$reportip/json")
ipapi_data=$(curl -s "http://ip-api.com/json/$reportip")

ip=$(echo $ipdata | grep -oP '(?<="ip":")[^"]+')
city=$(echo $ipdata | grep -oP '(?<="city":")[^"]+')
region=$(echo $ipdata | grep -oP '(?<="region":")[^"]+')
country=$(echo $ipdata | grep -oP '(?<="country_name":")[^"]+')
lat=$(echo $ipapi_data | grep -oP '(?<="lat":)[^,]+')
lon=$(echo $ipapi_data | grep -oP '(?<="lon":)[^,]+')
timezone=$(echo $ipapi_data | grep -oP '(?<="timezone":")[^"]+')
postal=$(echo $ipapi_data | grep -oP '(?<="zip":")[^"]+')
isp=$(echo $ipdata | grep -oP '(?<="org":")[^"]+')
asn=$(echo $ipdata | grep -oP '(?<="asn":")[^"]+')
country_code=$(echo $ipdata | grep -oP '(?<="country_code":")[^"]+')
currency=$(echo $ipdata | grep -oP '(?<="currency":")[^"]+')
languages=$(echo $ipdata | grep -oP '(?<="languages":")[^"]+')
calling_code=$(echo $ipdata | grep -oP '(?<="country_calling_code":")[^"]+')

current_date=$(date +"%Y-%m-%d")
current_time=$(date +"%H:%M:%S")

clear
printf "\e[1;37m"
printf "RH4X TECH REPORT\n"
printf "\n"
printf "Date: $current_date at $current_time\n"
printf "\n"
read -p $'  \e[1;37mTarget Name: \e[0m' target_name
read -p $'  \e[1;37mTarget Phone: \e[0m' target_phone
printf "\n"
printf "Collected Information:\n"
printf "\n"
printf "IP: $reportip\n"
printf "\n"
printf "%-25s : %-30s\n" "IP Address" "$ip"
printf "%-25s : %-30s\n" "City" "$city"
printf "%-25s : %-30s\n" "Region" "$region"
printf "%-25s : %-30s\n" "Country" "$country"
printf "%-25s : %-30s\n" "Latitude" "$lat"
printf "%-25s : %-30s\n" "Longitude" "$lon"
printf "%-25s : %-30s\n" "Time Zone" "$timezone"
printf "%-25s : %-30s\n" "Postal Code" "$postal"
printf "%-25s : %-30s\n" "ISP" "$isp"
printf "%-25s : %-30s\n" "ASN" "$asn"
printf "%-25s : %-30s\n" "Country Code" "$country_code"
printf "%-25s : %-30s\n" "Currency" "$currency"
printf "%-25s : %-30s\n" "Languages" "$languages"
printf "%-25s : %-30s\n" "Calling Code" "$calling_code"
printf "%-25s : %-30s\n" "Google Maps" "https://maps.google.com/?q=$lat,$lon"
if [[ -n "$target_name" ]]; then
printf "%-25s : %-30s\n" "Target Name" "$target_name"
fi
if [[ -n "$target_phone" ]]; then
printf "%-25s : %-30s\n" "Target Phone" "$target_phone"
fi
printf "\n"
printf "Tracking Purpose:\n"
printf "This recon was executed for security testing purposes.\n"
printf "\n"
printf "Remember... RH4X TECH is watching.\n"
printf "\e[0m"
printf "\n"
read -p $'  \e[1;37mGenerate report? [y/n]: \e[0m' generate
if [[ $generate == "y" || $generate == "Y" ]]; then
    filename="RH4X_REPORT_$(date +"%Y%m%d_%H%M%S").txt"
    printf "RH4X TECH REPORT\n" > $filename
    printf "\n" >> $filename
    printf "Date: $current_date at $current_time\n" >> $filename
    printf "\n" >> $filename
    if [[ -n "$target_name" ]]; then
    printf "Target Name: $target_name\n" >> $filename
    fi
    if [[ -n "$target_phone" ]]; then
    printf "Target Phone: $target_phone\n" >> $filename
    fi
    printf "\n" >> $filename
    printf "Collected Information:\n" >> $filename
    printf "\n" >> $filename
    printf "IP: $reportip\n" >> $filename
    printf "\n" >> $filename
    printf "%-25s : %-30s\n" "IP Address" "$ip" >> $filename
    printf "%-25s : %-30s\n" "City" "$city" >> $filename
    printf "%-25s : %-30s\n" "Region" "$region" >> $filename
    printf "%-25s : %-30s\n" "Country" "$country" >> $filename
    printf "%-25s : %-30s\n" "Latitude" "$lat" >> $filename
    printf "%-25s : %-30s\n" "Longitude" "$lon" >> $filename
    printf "%-25s : %-30s\n" "Time Zone" "$timezone" >> $filename
    printf "%-25s : %-30s\n" "Postal Code" "$postal" >> $filename
    printf "%-25s : %-30s\n" "ISP" "$isp" >> $filename
    printf "%-25s : %-30s\n" "ASN" "$asn" >> $filename
    printf "%-25s : %-30s\n" "Country Code" "$country_code" >> $filename
    printf "%-25s : %-30s\n" "Currency" "$currency" >> $filename
    printf "%-25s : %-30s\n" "Languages" "$languages" >> $filename
    printf "%-25s : %-30s\n" "Calling Code" "$calling_code" >> $filename
    printf "%-25s : %-30s\n" "Google Maps" "https://maps.google.com/?q=$lat,$lon" >> $filename
    printf "\n" >> $filename
    printf "Tracking Purpose:\n" >> $filename
    printf "This recon was executed for security testing purposes.\n" >> $filename
    printf "\n" >> $filename
    printf "Remember... RH4X TECH is watching.\n" >> $filename
    printf "\n"
    printf "\e[1;92mReport saved as: $filename\e[0m\n"
    sleep 3
fi
banner
menu
}

myipaddr() {
myipaddripapico=$(curl -s "https://ipapi.co//json")
myipaddripapicom=$(curl -s "http://ip-api.com/json/")
myip=$(echo $myipaddripapico | grep -oP '(?<="ip":")[^"]+')
mycity=$(echo $myipaddripapico | grep -oP '(?<="city":")[^"]+')
myregion=$(echo $myipaddripapico | grep -oP '(?<="region":")[^"]+')
mycountry=$(echo $myipaddripapico | grep -oP '(?<="country_name":")[^"]+')
mylat=$(echo $myipaddripapicom | grep -oP '(?<="lat":)[^,]+')
mylon=$(echo $myipaddripapicom | grep -oP '(?<="lon":)[^,]+')
mytime=$(echo $myipaddripapicom | grep -oP '(?<="timezone":")[^"]+')
mypostal=$(echo $myipaddripapicom | grep -oP '(?<="zip":")[^"]+')
myisp=$(echo $myipaddripapico | grep -oP '(?<="org":")[^"]+')
myasn=$(echo $myipaddripapico | grep -oP '(?<="asn":")[^"]+')
mycountrycode=$(echo $myipaddripapico | grep -oP '(?<="country_code":")[^"]+')
mycurrency=$(echo $myipaddripapico | grep -oP '(?<="currency":")[^"]+')
mylanguage=$(echo $myipaddripapico | grep -oP '(?<="languages":")[^"]+')
mycalling=$(echo $myipaddripapico | grep -oP '(?<="country_calling_code":")[^"]+')

banner
printf "\e[0m\n"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "IP Address" "$myip"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "City" "$mycity"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Region" "$myregion"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Country" "$mycountry"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Latitude" "$mylat"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Longitude" "$mylon"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Time Zone" "$mytime"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Postal Code" "$mypostal"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "ISP" "$myisp"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "ASN" "$myasn"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Country Code" "$mycountrycode"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Currency" "$mycurrency"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Languages" "$mylanguage"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Calling Code" "$mycalling"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;94m%-30s\e[0m\n" "Google Maps" "https://maps.google.com/?q=$mylat,$mylon"
sleep 5
printf "\e[0m\n"
printf "  \e[1;33m[01] Return To Main Menu\e[0m\n"
printf "  \e[1;33m[02] Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;33m>> \e[0m' mainorexit1

if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
banner
menu
elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1
else
printf " \e[1;91mInvalid option\e[0m\n"
sleep 1
banner
menu
fi
}

useripaddr() {
banner
printf "\e[0m\n"
printf "\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address: \e[0m\e[1;96m' useripaddress

ipaddripapico=$(curl -s "https://ipapi.co/$useripaddress/json")
ipaddripapicom=$(curl -s "http://ip-api.com/json/$useripaddress")
userip=$(echo $ipaddripapico | grep -oP '(?<="ip":")[^"]+')
usercity=$(echo $ipaddripapico | grep -oP '(?<="city":")[^"]+')
useregion=$(echo $ipaddripapico | grep -oP '(?<="region":")[^"]+')
usercountry=$(echo $ipaddripapico | grep -oP '(?<="country_name":")[^"]+')
userlat=$(echo $ipaddripapicom | grep -oP '(?<="lat":)[^,]+')
userlon=$(echo $ipaddripapicom | grep -oP '(?<="lon":)[^,]+')
usertime=$(echo $ipaddripapicom | grep -oP '(?<="timezone":")[^"]+')
userpostal=$(echo $ipaddripapicom | grep -oP '(?<="zip":")[^"]+')
userisp=$(echo $ipaddripapico | grep -oP '(?<="org":")[^"]+')
userasn=$(echo $ipaddripapico | grep -oP '(?<="asn":")[^"]+')
usercountrycode=$(echo $ipaddripapico | grep -oP '(?<="country_code":")[^"]+')
usercurrency=$(echo $ipaddripapico | grep -oP '(?<="currency":")[^"]+')
userlanguage=$(echo $ipaddripapico | grep -oP '(?<="languages":")[^"]+')
usercalling=$(echo $ipaddripapico | grep -oP '(?<="country_calling_code":")[^"]+')

banner
printf "\e[0m\n"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "IP Address" "$userip"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "City" "$usercity"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Region" "$useregion"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Country" "$usercountry"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Latitude" "$userlat"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Longitude" "$userlon"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Time Zone" "$usertime"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Postal Code" "$userpostal"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "ISP" "$userisp"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "ASN" "$userasn"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Country Code" "$usercountrycode"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Currency" "$usercurrency"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Languages" "$userlanguage"
printf "  \e[1;33m%-15s : \e[1;92m%-30s\e[0m\n" "Calling Code" "$usercalling"
printf "\e[0m\n"
printf "  \e[1;33m%-15s : \e[1;94m%-30s\e[0m\n" "Google Maps" "https://maps.google.com/?q=$userlat,$userlon"
sleep 5
printf "\e[0m\n"
printf "  \e[1;33m[01] Return To Main Menu\e[0m\n"
printf "  \e[1;33m[02] Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;33m>> \e[0m' mainorexit2

if [[ $mainorexit2 == 1 || $mainorexit2 == 01 ]]; then
banner
menu
elif [[ $mainorexit2 == 2 || $mainorexit2 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1
else
printf " \e[1;91mInvalid option\e[0m\n"
sleep 1
banner
menu
fi
}

menu() {
printf "\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m01\e[0m\e[1;31m]\e[0m\e[1;33m My IP\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m02\e[0m\e[1;31m]\e[0m\e[1;33m Track IP\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m03\e[0m\e[1;31m]\e[0m\e[1;33m Generate Report\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m04\e[0m\e[1;31m]\e[0m\e[1;33m Phone Tracker\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m05\e[0m\e[1;31m]\e[0m\e[1;33m Scan Ports\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m00\e[0m\e[1;31m]\e[0m\e[1;33m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Select An Option \e[0m\e[1;96m: \e[0m\e[1;93m\en' option

if [[ $option == 1 || $option == 01 ]]; then
myipaddr
elif [[ $option == 2 || $option == 02 ]]; then
useripaddr
elif [[ $option == 3 || $option == 03 ]]; then
generate_report
elif [[ $option == 4 || $option == 04 ]]; then
phone_info
elif [[ $option == 5 || $option == 05 ]]; then
scan_ports
elif [[ $option == 0 || $option == 00 ]]; then
sleep 1
printf "\e[0m\n"
printf "\e[0m\n"
exit 1
else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi
}

banner
menu
