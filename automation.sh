#!/bin/bash

url=$1

if [ ! -d "$url" ]; then
	mkdir $url
fi

if [ ! -d "$url/recon" ]; then
	mkdir $url/recon
fi

if [ ! -d 'surl/recon/gowitness' ]; then 
	mkdir $url/recon/gowitness
fi 

if [ ! -d "$url/recon/scans" ]; then
	mkdir $url/recon/scans
fi 

if [ ! -d "$url/recon/httprobe" ]; then
	mkdir $url/recon/httprobe
fi 

if [ ! -d "$url/recon/potential takeovers" ]; then
	mkdir $url/recon/potential_takeovers
fi

if [ ! -d "$url/recon/wayback" ]; then
	mkdir $url/recon/wayback 
fi

if [ ! -d "$url/recon/wayback/params" ]; then
	mkdir surl/recon/wayback/params
fi

if [ ! -d "$url/recon/wayback/extensions" ]; then 
	mkdir $url/recon/wayback/extensions
fi

if [ ! -f "$url/recon/httprobe/alive.txt" ]; then
    touch $url/recon/httprobe/alive.txt
fi

if [ ! "$url/recon/final.txt" ]; then
	touch $url/recon/final.txt
fi

echo "[+] haarvesting subdomains with assetfinder...."
assetfinder $url >>/recon/asses.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
rm $url/recon/assets.txt

#echo "[+] Double checking for subdomains with amass..."
amass enum -d $url >> $url/recon/f.txt
#sort -u $url/recon/f.txt >> $url/recon/final.txt
#rm $url/recon/f.txt

echo "[+] Probing for alive domains..."
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | tee -a $url/recon/httprobe/a.txt
sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive.txt
rm $url/recon/httprobe/a.txt

echo "[+] checking for possible subdomain takeover...."

if [! -f "$url/recon/potentian_takeover"]; then
	touch $url/recon/potential_takeovers/potential_takeover.txt
fi

subjack -w $url/recon/final/txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints/json -v 3 -o $url/recon/potential_takeovers/potentail_takeovers.txt

echo " [+] Scanning for open ports....."
nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt

echo "[+] scraping waybackdata...."
cat $url/recon/final.txt | wayback >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt


