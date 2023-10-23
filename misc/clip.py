#!/usr/bin/env python3
import sys
from pyperclip import copy


def clip(data, args=None):
	if not args or args.keep_head is False:
		data = data.lstrip()
	if not args or args.keep_tail is False:
		data = data.rstrip()

	if isinstance(data, bytes):
		try:
			data = data.decode()
		except UnicodeDecodeError:
			print('Failed to decode input data.', file=sys.stderr)
			sys.exit(2)
	copy(data)
	if args and args.print:
		print(data, end='')


def main():
	from argparse import ArgumentParser

	parser = ArgumentParser(prog='clip', description='Copy text to clipboard from file or STDIN')
	parser.add_argument('source', nargs='?', action='store', help='Source file or text')

	source_options = parser.add_argument_group('Source options')
	source_type = source_options.add_mutually_exclusive_group()
	source_type.add_argument('-t', '--text', action='store_true', help='Force text mode')
	source_type.add_argument('-f', '--file', action='store_true', help='Force file mode')

	data_options = parser.add_argument_group('Data handling options')
	data_options.add_argument('-b', '--keep-head', action='store_true', help='Do not strip whitespace from beginning of data')
	data_options.add_argument('-a', '--keep-tail', action='store_true', help='Do not strip trailing whitespace')
	data_options.add_argument('-p', '--print', action='store_true', help='Direct copied text back to STDIN')

	args = parser.parse_args()

	if args.source is None:
		data = sys.stdin.read().encode()
	elif args.file is True:
		with open(args.source, 'rb') as infile:
			data = infile.read()
	else:
		data = args.source.encode()

	clip(data, args)


if __name__ == '__main__':
	if len(sys.argv) < 2:
		try:
			clip(sys.stdin.read())
		except UnicodeDecodeError:
			print('Failed to decode input data.', file=sys.stderr)
			sys.exit(2)
		except KeyboardInterrupt:
			sys.exit(1)
	else:
		main()