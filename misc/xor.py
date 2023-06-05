#!/usr/bin/env python3
import argparse
import sys

def xor(d, k):
  return bytes([d[i]^k[i%len(k)] for i in range(len(d))])

def hex(x):
  return bytes.fromhex(x)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--input', metavar='FILE', required=True, help='File to encrypt/decrypt')
  parser.add_argument('-k', '--key', metavar='HEX', required=True, type=hex, help='Key (hex)')
  parser.add_argument('-o', '--output', metavar='FILE', required=True, help='Output file')
  args = parser.parse_args()

  try:
    with open(args.input, 'rb') as i, open(args.output, 'wb') as o:
      o.write(xor(i.read(), args.key))
  except FileNotFoundError:
    print(f'Input file does not exist!')
    sys.exit(1)

if __name__ == '__main__':
  main()
