#!/bin/bash

# Generates a pseudo-random string with a given suffix (optional)
# Usually used to generate random file names

len=$((8 + $RANDOM % 8))
openssl rand -base64 $len |
  tr -d '='  |
  tr '+' '-' |
  tr '/' '_' |
  sed "s/$/$1/g"
