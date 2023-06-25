#!/usr/bin/env bash

ctf_scan="
Author:  Bryan McNulty
Contact: bryanmcnulty@protonmail.com

Just a fancy nmap wrapper that I often use
during the initial recon phase for CTFs

OS: Linux

PATH requirements:
  - sudo
  - nmap
"

[ -z "$1" ] && echo "$0 <IP>" && exit

# UDP ports for DNS,TFTP,KRB,RPCBIND,NTP,SNMP,IPMI,IKE,ISAKMP
udp_ports="53,69,88,111,123,161,162,500,623,4500,10161,10162"
# All TCP ports
tcp_ports="-"

log_dir=$(mktemp -d)
cd $log_dir

echo "[+] Starting TCP scan"
sudo nmap -v -Pn -sS -n -p $tcp_ports --min-rate=1000 -T4 $1 -oN ./tcp-discovery.log

open_tcp_ports=$(grep -E '^[0-9]' ./tcp-discovery.log |
	cut -d '/' -f 1 |
	tr '\n' ',' |
	sed 's/,$//')

[ -n "$open_tcp_ports" ] && echo "[+] Found relevant TCP ports: $open_tcp_ports"
echo "[+] Starting UDP scan"
sudo nmap -v -Pn -sU -n -p $udp_ports --min-rate=50 -T4 $1 -oN ./udp-discovery.log

open_udp_ports=$(grep -E '^[0-9].* *open +' ./udp-discovery.log |
	cut -d '/' -f 1 |
	tr '\n' ',' |
	sed 's/,$//')

[ -n "$open_udp_ports" ] && echo "[+] Found open UDP ports: $open_udp_ports"

mkdir ./tcp ./udp
[ -z $open_tcp_ports ] || sudo nmap $1 -sS -n -p "$open_tcp_ports" -sV -sC -oA ./tcp/scan
[ -z $open_udp_ports ] || sudo nmap $1 -sU -n -p "$open_udp_ports" -sV -sC -oA ./udp/scan

cd $OLDPWD
mkdir -p ./logs

dir="./logs/ctfscan-$1-$(date +%s)"
mv $log_dir $dir
sudo chown -R "$USER:$USER" $dir

echo "[*] Done!"
