#!/usr/bin/env python3


import docker_ipsec
import ipsecparse
import sys
import pyroute2
import iptc
import argparse

def main():
    desc = 'Start and stop IPSec tunnels while allowing docker containers to route traffic down the tunnels'
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('command', type=str, choices=set(('up', 'down')),
                        help='Start or stop an IPSec tunnel')

    parser.add_argument('connection', type=str, default='')

    parser.add_argument('--docker-bridge', dest='dockerBridge', type=str, default='docker0',
                        help='Name of the docker bridge')
    parser.add_argument('--ipsec-route-table', dest='ipsecRouteTable', type=int, default=220,
                        help='Route table containing IPSec routes')
    parser.add_argument('--ipsec-conf', dest='ipsecConf', type=str, default='/etc/ipsec.conf',
                        help='IPSec configuration file')
    
    parsedArgs = parser.parse_args()

    with open(parsedArgs.ipsecConf, 'rt') as ipsecConfFile:
        ipsecConfStr = ipsecConfFile.read()

    ipsecConnectionName = parsedArgs.connection
    if (ipsecConnectionName == ''):
        ipsecConf = ipsecparse.loads(ipsecConfStr)
        ipsecConnectionEntries = map(lambda e: (e[0][0], e[1]),
                                    filter(lambda e: e[0][0] == 'conn' and e[0][1] != '%default',
                                           ipsecConf.entries()))
        ipsecConnections = dict(ipsecConnectionEntries)
        if (len(ipsecConnections) != 1):
            print('IPSec configuration in {0} contains more than one connection, specify which one:')
            for c in ipsecConnections.keys():
                print(c + '\n')
            return 1

        ipsecConnectionName = tuple(ipsecConnections.keys())[0]

    if (parsedArgs.command == 'down'):
        docker_ipsec.removeIPTablesRules()
        if (not docker_ipsec.ipsec('down', ipsecConnectionName, verbose=True)):
            return 1
        return 0

    ipRoute = pyroute2.IPRoute()
    dockerInfo = docker_ipsec.DockerInfo(ipRoute=ipRoute, dockerBridgeName=parsedArgs.dockerBridge)

    if (not docker_ipsec.ipsec('up', ipsecConnectionName, verbose=True)):
        return 1

    ipsecInfo = docker_ipsec.IPSecInfo(ipRoute=ipRoute, ipsecTableIndex=parsedArgs.ipsecRouteTable)

    def ipsecEntryToIPTablesRule(e):
        outputInterfaceIndex = e.outputInterfaceIndex()
        outputInterface = docker_ipsec.getInterfaceNameForIndex(outputInterfaceIndex, ipRoute=ipRoute)
        return (e.sourceIP(), outputInterface, e.destCIDR(), dockerInfo.cidr())

    rules = tuple(map(ipsecEntryToIPTablesRule, ipsecInfo.entries()))
    table = iptc.Table(iptc.Table.NAT)
    table.autocommit = False
    for rule in rules:
        docker_ipsec.installIPTablesRule(table, *rule)
    table.commit()

if __name__ == '__main__':
    sys.exit(main())




    

