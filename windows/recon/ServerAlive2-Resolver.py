#!/usr/bin/env python3

import sys, argparse, re

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter


def main():
    parser = argparse.ArgumentParser(prog='IOXIDResolver', description='A program to enumerate network interfaces on a remote server using the RPC `ServerAlive2` method')
    parser.add_argument('target', help='Target hostname/IP address')
    args = parser.parse_args()

    authLevel = RPC_C_AUTHN_LEVEL_NONE

    stringBinding = r'ncacn_ip_tcp:%s' % args.target
    rpctransport = transport.DCERPCTransportFactory(stringBinding)

    portmap = rpctransport.get_dce_rpc()
    portmap.set_auth_level(authLevel)
    portmap.connect()

    objExporter = IObjectExporter(portmap)
    bindings = objExporter.ServerAlive2()

    rexIPAddress = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')

    for binding in bindings:
        netAddr = binding['aNetworkAddr'].replace('\0', '')

        if rexIPAddress.match(netAddr):
            print('Address: ', netAddr)
        else:
            print('Hostname:', netAddr)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Exiting..')
        sys.exit(1)
