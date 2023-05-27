#!/usr/bin/env python3
'''
encodes a given string using URL/percent encoding
'''

from sys import argv
from urllib.parse import quote

if len(argv) > 1:
  print(quote(' '.join(argv[1:])))
else:
  print('./urle <STRING>')
