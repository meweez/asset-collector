#!/bin/bash



GITHUB_TOKEN=""




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

if ! type "curl" > /dev/null; then
  echo -e "  ${red}[-]${NC} cURL is not installed ! Please install it and try again."
  exit
fi

if ! command -v subfinder &> /dev/null
then
    echo -e "  ${red}[-]${NC} subfinder could not be found !"
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
subfinder -d $domain -all -o results/$domain/subfinder.txt &> /dev/null
#=======================================================================

#crt.sh on Domain
#=======================================================================
echo -e "  ${green}[+]${NC} crt.sh"
query=$(cat <<-END
        SELECT
            ci.NAME_VALUE
        FROM
            certificate_and_identities ci
        WHERE
            plainto_tsquery('certwatch', '$domain') @@ identities(ci.CERTIFICATE)
END
)
echo "$query" | psql -t -h crt.sh -p 5432 -U guest certwatch | sed 's/ //g' | egrep ".*.\.$domain" | sed 's/*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u | uniq | tee -a results/$domain/crtsh.txt &> /dev/null
# curl -s "https://crt.sh/?q=$domain&output=json" | tr '\0' '\n' | jq -r ".[].common_name,.[].name_value" | sort -u | uniq | tee -a results/$domain/crtsh.txt &> /dev/null
#=======================================================================

#Subdomain enumeration in Github
#=======================================================================
if [[ ! -z "$GITHUB_TOKEN" ]]
then
  echo -e "  ${green}[+]${NC} Github"
  github-subdomains -d $domain -e -o results/$domain/github.txt -t $GITHUB_TOKEN &> /dev/null
fi
#=======================================================================


#Subdomain enumeration in SourceGraph
#=======================================================================
echo -e "  ${green}[+]${NC} SourceGraph"
q=$(echo $domain| sed -e 's/\./\\\./g')
src search -json '([a-z\-]+)?:?(\/\/)?([a-zA-Z0-9]+[.])+('${q}') count:5000 fork:yes archived:yes' | jq -r '.Results[] | .lineMatches[].preview, .file.path' | grep -oiE '([a-zA-Z0-9]+[.])+('${q}')' | awk '{ print tolower($0) }' | sort -u | tee -a results/$domain/sourcegraph.txt
#=======================================================================

#Subdomain enumeration using AbuseDB
#=======================================================================
echo -e "  ${green}[+]${NC} AbuseDB"
curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e "s/$/.$domain/" | tee -a results/$domain/abusedb.txt &> /dev/null
#=======================================================================

# Combine all results and remove duplicates
#=======================================================================
echo -e "${blue}[!]${NC} Combining results and removing duplicates..."
cat results/$domain/*.txt | sort -u > results/$domain/all_subs.txt

# rm results/$domain/abusedb.txt results/$domain/github.txt results/$domain/crtsh.txt results/$domain/subdomain_certificate.txt results/$domain/assetfinder.txt results/$domain/subfinder.txt results/$domain/sourcegraph.txt
echo -e "${blue}[!]${NC} Subdomain enumeration complete! Results saved to results/$domain/all_subs.txt :))"
#=======================================================================

#Get PTR and TXT records of subdomains
#=======================================================================
cat results/$domain/all_subs.txt | dnsx -resp-only -silent | dnsx -silent -ptr >> results/$domain/resource.txt
cat results/$domain/all_subs.txt | dnsx -txt -silent >> results/$domain/resource.txt
#=======================================================================

# Name resolution of subdomains 
#=======================================================================
echo -e "${blue}[!]${NC} Performing name resolution"
cat results/$domain/all_subs.txt | dnsx -silent -resp-only | sort -u | tee results/$domain/all_subs_ip.txt  &> /dev/null
#=======================================================================
