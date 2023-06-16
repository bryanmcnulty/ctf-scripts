#!/bin/bash
# -*- Use openssl to calculate NT hash of stdin -*-
# User account:     $ echo -n P@ssw0rd | nt
# Machine account:  $ echo -n P@ssw0rd | nt -m

cat /dev/stdin |
  ([ "$1" != "-m" ] && iconv -t utf16le) |
  openssl dgst -md4 |
  cut -d ' ' -f 2
