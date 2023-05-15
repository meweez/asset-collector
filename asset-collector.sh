#!/bin/bash

export GITHUB_TOKEN=
# Check for requirements
#=======================================================================
if ! type "go" > /dev/null; then
  echo "Go is not installed ! Please install it and try again."
  exit
fi

if ! type "whois" > /dev/null; then
  echo "Whois is not installed ! Please install it and try again."
  exit
fi

if ! type "jq" > /dev/null; then
  echo "jq is not installed ! Please install it and try again."
  exit
fi

if command -v "mapcidr" > /dev/null; then
  echo "mapcidr is not installed ! Please install it and try again."
  exit
fi

if command -v "dnsx" > /dev/null; then
  echo "dnsx is not installed ! Please install it and try again."
  exit
fi

if ! type "dig" > /dev/null; then
  echo "dig is not installed ! Please install it and try again."
  exit
fi

if ! type "curl" > /dev/null; then
  echo "cURL is not installed ! Please install it and try again."
  exit
fi

if ! type "openssl" > /dev/null; then
  echo "OpenSSL is not installed ! Please install it and try again."
  exit
fi

if ! command -v subfinder &> /dev/null
then
    echo "subfinder could not be found !"
    exit
fi

if ! command -v assetfinder &> /dev/null
then
    echo "assetfinder could not be found !"
    exit
fi

if ! command -v github-subdomains &> /dev/null
then
    echo "github-subdomains could not be found !"
    exit
fi
#=======================================================================

# Get target domain name from user
echo -n "Enter the target domain name: "
read domain

# Create output directory if it doesn't exist
if [ ! -d "$domain" ]; then
    mkdir $domain
fi

# Run subfinder and save results to file
#=======================================================================
echo "Running subfinder..."
subfinder -d $domain -all -o $domain/subfinder.txt
#=======================================================================

# Run assetfinder and save results to file
#=======================================================================
echo "Running assetfinder..."
assetfinder --subs-only $domain > $domain/assetfinder.txt
#=======================================================================

#Certificate Search on Domain
#=======================================================================
cert=$(echo | openssl s_client -showcerts -servername $domain -connect $domain:443 2>/dev/null | openssl x509 -inform pem -noout -text)
san=$(echo "$cert" | grep -A1 "X509v3 Subject Alternative Name:" | tail -n1)
san_urls=$(echo "$san" | grep -o "DNS:[^,]*" | sed 's/DNS://g' | xargs -n1 | sed 's/^\s*//' | sed 's/\s*$//')
echo $san_urls | tee -a $domain/subdomain_certificate.txt
#=======================================================================

#crt.sh on Domain
#=======================================================================
curl -s "https://crt.sh/?q=$domain&output=json" | tr '\0' '\n' | jq -r ".[].common_name,.[].name_value" | sort -u | uniq | tee -a $domain/crtsh.txt
#=======================================================================

#Subdomain enumeration in Github
#=======================================================================
github-subdomains -d $domain -e -o $domain/github.txt
#=======================================================================

#Subdomain enumeration using AbuseDB
#=======================================================================
curl -s "https://www.abuseipdb.com/whois/$domain" -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e 's/$/."$domain"/' | tee -a $domain/abusedb.txt
#=======================================================================

# Combine all results and remove duplicates
#=======================================================================
echo "Combining results and removing duplicates..."
cat $domain/*.txt | sort -u > $domain/all_subs.txt

echo "Subdomain enumeration complete! Results saved to $domain/all_subs.txt"
#=======================================================================

#Get PTR and TXT records of subdomains
#=======================================================================
while read sub; do
  sub_ip=$(dig +short $sub)
  for i in "${sub_ip[@]}"; do
    ptr_record=$(dig -x $i +short)
    if [ ! -z "$ptr_record" ]; then
      echo $ptr_record >> $domain/resource.txt
    fi
  done
  
  txt_record=$(dig $sub TXT +short)
  if [ ! -z "$txt_record" ]; then
    echo $txt_record >> $domain/resource.txt
  fi
done < $domain/all_subs.txt
#=======================================================================

# Name resolution of subdomains and remove CDN IP's
#=======================================================================
echo "Performing name resolution and filtering CDN IP's..."
cat $domain/all_subs.txt | dnsx -silent -resp-only | tee $domain/res_subs.txt
cat $domain/res_subs.txt | mapcidr -filter-ip cdns.txt | tee $domain/ips.txt
#=======================================================================

# Scanning port on No CDN IPs
#=======================================================================
echo "Scanning IPs for opening ports..."

cat $domain/ips.txt | naabu -silent | tee $domain/portscan.txt
#=======================================================================

# Certificate search again
#=======================================================================
echo "Certificate Search again on IP and open ports..."
while read ip_port; do
  ipport_cert=$(echo | openssl s_client -showcerts -connect $ip_port 2>/dev/null | openssl x509 -inform pem -noout -text)
  if [ $ipport_cert != "Could not read certificate from <stdin>" ]; then
    san2=$(echo "$ipport_cert" | grep -A1 "X509v3 Subject Alternative Name:" | tail -n1)
    san_urlss=$(echo "$san2" | grep -o "DNS:[^,]*" | sed 's/DNS://g' | xargs -n1 | sed 's/^\s*//' | sed 's/\s*$//')
    for i in "${san_urlss[@]}"; do
      if [ "$i" != "$domain" ]; then
        echo $san_urlss | tee -a $domain/resource.txt
      fi
    done
  fi
done < $domain/portscan.txt
