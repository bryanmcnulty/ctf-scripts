#!/usr/bin/env bash

ctf_vhbrute='
Author:  Bryan McNulty
Contact: bryanmcnulty@protonmail.com

Unnecessary ffuf wrapper for VHOST enumeration

OS: Linux

PATH requirements:
  - curl
  - ffuf
  - gzip
  - openssl
'
[ -z $2 ] && echo 'vhbrute <URL> <HOSTNAME> [WORDLIST]' && exit 1

url="$1"
vhost="$2"
wordlist="$3"

rand_sub="$(openssl rand -hex 12).$vhost"
res_vars=$(curl "$url" -H "Host: $rand_sub" -s -w '%{http_code},%{size_download}' -o /dev/null)
res_code=$(echo $res_vars | cut -d, -f1)
res_size=$(echo $res_vars | cut -d, -f2)

echo "VHOST fallback response code:   $res_code"
echo "VHOST fallback response length: $res_size"

tmp=$(mktemp)

clean() {
	rm -f "$tmp"
}

if [ -z "$wordlist" ]
then
    # download subdomain wordlist
	# 100k / 10k / 1k (internet connection required)
	wl_size="100k"

	wordlist=$tmp
	trap clean EXIT

	download="https://raw.githubusercontent.com/bryanmcnulty/ctf-wordlists/main/subdomains/subdomains-top1million/subdomains-$wl_size.gz"
	curl -s -o - "$download" | gunzip - > "$wordlist"
	echo "Downloaded subdomain names:     $wl_size"
fi

[[ ! "$url" =~ ^https?:// ]] && url="http://$url"

echo -e 'Fuzzing VHOSTS under \033[1m'"$vhost"'\033[0m...'
ffuf -u "$url" \
	-w "$wordlist:SUB" -H "Host: SUB.$vhost" \
	-mc "all" -fmode "and" -fc "$res_code" -fs "$res_size"
