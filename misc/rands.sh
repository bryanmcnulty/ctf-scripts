#!/bin/bash

# Generates a pseudo-random string
# Usually used to generate random file names

len=$((8 + $RANDOM % 9))
openssl rand -base64 "$len" |
  tr -d '='  |
  tr '+' '-' |
  tr '/' '_' |
  sed "s/^-/_/g"
