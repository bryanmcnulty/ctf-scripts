#!/usr/bin/env python3
import websocket, argparse

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('URL', metavar='ws://HOST[:PORT]', help='Target URL')
  parser.add_argument('-d', '--data', help='Data to send')
  args = parser.parse_args()

  ws = websocket.WebSocket()
  if not args.URL.startswith('ws://'):
    args.URL = 'ws://'+args.URL

  ws.connect(args.URL)
  ws.send(args.data or '{}')
  response = ws.recv()
  if response:
    print(response)

if __name__ == '__main__':
  main()
