#!/bin/bash
# Use openssl to calculate NT hash of stdin

cat /dev/stdin      |
  iconv -t utf16le  |
  openssl dgst -md4 |
  cut -d ' ' -f 2
