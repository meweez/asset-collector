#!/bin/bash



GITHUB_TOKEN="Your github token"




red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
NC='\033[0m'

printf "
                    _                  _ _           _             
  __ _ ___ ___  ___| |_       ___ ___ | | | ___  ___| |_ ___  _ __ 
 / _\` / __/ __|/ _ \ __|____ / __/ _ \| | |/ _ \/ __| __/ _ \| '__|
| (_| \__ \__ \  __/ ||_____| (_| (_) | | |  __/ (__| || (_) | |   
 \__,_|___/___/\___|\__|     \___\___/|_|_|\___|\___|\__\___/|_|   
                                                                   

			                           ${cyan}Developed by MHA${NC}	     			                  
                                                            ${yellow}mha4065.com${NC}              		               

"

usage() { echo -e "${yellow}Usage:${NC} ./asset-collector.sh -d domain.tld" 1>&2; exit 1; }

while getopts "d:" flag
do
    case "${flag}" in
        d) domain=${OPTARG#*//};;
        \? ) usage;;
        : ) usage;;
    *) usage;;
    esac
done

if [[ -z "${domain}" ]]; then
  usage
fi                                          


# Check for requirements
#=======================================================================
echo
echo -e "${blue}[!]${NC} Check the requirements :"

if ! type "whois" > /dev/null; then
  echo -e "  ${red}[-]${NC} Whois is not installed ! Please install it and try again."
  exit
fi

if ! type "jq" > /dev/null; then
  echo -e "  ${red}[-]${NC} jq is not installed ! Please install it and try again."
  exit
fi

if ! command -v "mapcidr" > /dev/null; then
  echo -e "  ${red}[-]${NC} mapcidr is not installed ! Please install it and try again."
  exit
fi

if ! command -v "dnsx" > /dev/null; then
  echo -e "  ${red}[-]${NC} dnsx is not installed ! Please install it and try again."
  exit
fi

if ! type "dig" > /dev/null; then
  echo -e "  ${red}[-]${NC} dig is not installed ! Please install it and try again."
  exit
fi

if ! type "curl" > /dev/null; then
  echo -e "  ${red}[-]${NC} cURL is not installed ! Please install it and try again."
  exit
fi

if ! type "openssl" > /dev/null; then
  echo -e "  ${red}[-]${NC} OpenSSL is not installed ! Please install it and try again."
  exit
fi

if ! command -v subfinder &> /dev/null
then
    echo -e "  ${red}[-]${NC} subfinder could not be found !"
    exit
fi

if ! command -v assetfinder &> /dev/null
then
    echo -e "  ${red}[-]${NC} assetfinder could not be found !"
    exit
fi

if ! command -v github-subdomains &> /dev/null
then
    echo -e "  ${red}[-]${NC} github-subdomains could not be found !"
    exit
fi

echo -e "   ${green}[+]${NC} All requirements are installed :)"
#=======================================================================

# Create output directory if it doesn't exist
if [ ! -d "results" ]; then
    mkdir "results"
    if [ ! -d "results/$domain" ]; then
      mkdir "results/$domain"
    fi
fi

# Run subfinder and save results to file
#=======================================================================
echo
echo -e "${blue}[!]${NC} Subdomain enumeration :"

echo -e "  ${green}[+]${NC} subfinder"
subfinder -d $domain -all -o results/$domain/subfinder.txt
#=======================================================================

# Run assetfinder and save results to file
#=======================================================================
echo -e "  ${green}[+]${NC} assetfinder"
assetfinder --subs-only $domain > results/$domain/assetfinder.txt
#=======================================================================

#crt.sh on Domain
#=======================================================================
echo -e "  ${green}[+]${NC} crt.sh"
curl -s "https://crt.sh/?q=$domain&output=json" | tr '\0' '\n' | jq -r ".[].common_name,.[].name_value" | sort -u | uniq | tee -a results/$domain/crtsh.txt
#=======================================================================

#Subdomain enumeration in Github
#=======================================================================
echo -e "  ${green}[+]${NC} Github"
github-subdomains -d $domain -e -o results/$domain/github.txt -t $GITHUB_TOKEN
#=======================================================================

#Subdomain enumeration using AbuseDB
#=======================================================================
echo -e "  ${green}[+]${NC} AbuseDB"
curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e 's/$/."$domain"/' | tee -a results/$domain/abusedb.txt
#=======================================================================

# Combine all results and remove duplicates
#=======================================================================
echo -e "${blue}[!]${NC} Combining results and removing duplicates..."
cat results/$domain/*.txt | sort -u > results/$domain/all_subs.txt

rm results/$domain/abusedb.txt results/$domain/github.txt results/$domain/crtsh.txt results/$domain/subdomain_certificate.txt results/$domain/assetfinder.txt results/$domain/subfinder.txt 
echo -e "${blue}[!]${NC} Subdomain enumeration complete! Results saved to results/$domain/all_subs.txt :))"
#=======================================================================

#Get PTR and TXT records of subdomains
#=======================================================================
cat results/$domain/all_subs.txt | dnsx -resp-only -silent | dnsx -silent -ptr >> results/$domain/resource.txt
cat results/$domain/all_subs.txt | dnsx -txt -silent >> results/$domain/resource.txt
#=======================================================================

# Name resolution of subdomains and remove CDN IP's
#=======================================================================
echo -e "${blue}[!]${NC} Performing name resolution and filtering CDN IP's..."
cat results/$domain/all_subs.txt | dnsx -silent -resp-only | tee results/$domain/res_subs.txt
cat results/$domain/res_subs.txt | mapcidr -filter-ip cdns.txt | tee results/$domain/ips.txt
#=======================================================================

# Scanning port on No CDN IPs
#=======================================================================
echo -e "${blue}[!]${NC} Scanning IPs for opening ports..."

cat results/$domain/ips.txt | naabu -silent | tee results/$domain/portscan.txt
#=======================================================================

# Certificate search again
#=======================================================================
echo -e "${blue}[!]${NC} Certificate Search again on IP and open ports..."
while read ip_port; do
  ipport_cert=$(echo | openssl s_client -showcerts -connect $ip_port 2>/dev/null | openssl x509 -inform pem -noout -text)
  if [ $ipport_cert != "Could not read certificate from <stdin>" ]; then
    san2=$(echo "$ipport_cert" | grep -A1 "X509v3 Subject Alternative Name:" | tail -n1)
    san_urlss=$(echo "$san2" | grep -o "DNS:[^,]*" | sed 's/DNS://g' | xargs -n1 | sed 's/^\s*//' | sed 's/\s*$//')
    for i in "${san_urlss[@]}"; do
      if [ "$i" != "$domain" ]; then
        echo $san_urlss | tee -a results/$domain/resource.txt
      fi
    done
  fi
done < results/$domain/portscan.txt
