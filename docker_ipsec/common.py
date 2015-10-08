import socket
import pyroute2
import netaddr
import tempfile
import iptc
import json
import subprocess

def toJSON(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True)

class IPSecInfoEntry:
    def __init__(self, tableEntry):
        attrs = dict(tableEntry.get('attrs', []))
        if (len(attrs) == 0):
            raise RuntimeError('Unable to get attrs from table entry: {0}'.format(toJSON(tableEntry)))
        self.__dest = attrs.get('RTA_DST', None)
        if (self.__dest is None):
            raise RuntimeError('Unable to get destination from table entry: {0}'.format(toJSON(tableEntry)))
        
        self.__src = attrs.get('RTA_PREFSRC', None)
        if (self.__dest is None):
            raise RuntimeError('Unable to get source from table entry: {0}'.format(toJSON(tableEntry)))

        self.__gateway = attrs.get('RTA_GATEWAY', None)
        if (self.__dest is None):
            raise RuntimeError('Unable to get gateway from table entry: {0}'.format(toJSON(tableEntry)))

        self.__interfaceIndex = attrs.get('RTA_OIF', None)
        if (self.__interfaceIndex is None):
            raise RuntimeError('Unable to get output interface from table entry: {0}'.format(tableEntry))
        
        self.__destLen = tableEntry.get('dst_len', None)
        if (self.__destLen is None):
            raise RuntimeError('Unable to get destination mask')

    def destCIDR(self):
        return '{0}/{1}'.format(self.__dest, self.__destLen)

    def outputInterfaceIndex(self):
        return self.__interfaceIndex

    def sourceIP(self):
        return self.__src


class IPSecInfo:

    def __init__(self, ipsecTableIndex=220, ipRoute=None):
        ipRoute = ipRoute if ipRoute is not None else pyroute2.IPRoute()

        ipSecRoutes = ipRoute.get_routes(table=ipsecTableIndex)
        self.__entries = tuple(map(IPSecInfoEntry, ipSecRoutes))

    def entries(self):
        return self.__entries


class DockerInfo:

    def __init__(self, dockerBridgeName='docker0', ipRoute=None):
        ipRoute = ipRoute if ipRoute is not None else pyroute2.IPRoute()

        dockerAddresses = ipRoute.get_addr(label=dockerBridgeName)
        if (len(dockerAddresses) != 1):
            raise RuntimeError('Expected 1 docker address, found {0}'.format(toJSON(dockerAddresses)))

        dockerAddress = dockerAddresses[0]

        attrs = dockerAddress.get('attrs', None)
        if (attrs is None):
            raise RuntimeError('Enable to get attrs from docker address: {0}'.format(toJSON(dockerAddress)))
        attrs = dict(attrs)
        self.__ip = attrs.get('IFA_LOCAL', None)
        if (self.__ip is None):
            raise RuntimeError('Unable to get docker ip address: {0}'.format(toJSON(dockerAddress)))

        self.__ipLen = dockerAddress.get('prefixlen', None)
        if (self.__ipLen is None):
            raise RuntimeError('Unable to get docker net mask: {0}'.format(toJSON(dockerAddress)))

        self.__net = netaddr.IPNetwork('{0}/{1}'.format(self.__ip, self.__ipLen))

    def cidr(self):
        return '{0}/{1}'.format(str(self.__net.network), self.__ipLen)

def getInterfaceNameForIndex(interfaceIndex, ipRoute=None):
    ipRoute = ipRoute if ipRoute is not None else pyroute2.IPRoute()
    links = ipRoute.get_links(interfaceIndex)
    if (len(links) != 1):
        raise RuntimeError('Expected one link for interface index, found {0}'.format(links))

    link = links[0]
    name = dict(links.get('attrs', [])).get('IFLA_IFNAME', None)
    if (name is None):
        raise RuntimeError('Unable to get interface name: {0}'.format(toJSON(links)))
    return name

def installIPTablesRule(table, virtualIP, outInterface, destCIDR, dockerCIDR):
    rule = iptc.Rule()
    rule.in_interface = '*'
    rule.out_interface = outInterface
    rule.src = dockerCIDR
    rule.dst = destCIDR

    comment = rule.create_match('comment')
    commentDict = {
        'vip' : virtualIP,
        'destCIDR' : destCIDR,
        'dockerCIDR' : dockerCIDR
    }
    commentJSONStr=json.dumps(commentDict, ensure_ascii=True, sort_key=True, separators=(',', ':'))
    comment.set_parameter('comment', 'docker_ipsec:{0}'.format(commentJSONStr))

    target = rule.create_target('SNAT')
    target.set_parameter('to-source', virtualIP)

    chain = iptc.Chain(table, 'POSTROUTING')

    chain.insert_rule(rule)
    
def removeIPTablesRules():
    table = iptc.Table(iptc.Table.NAT)
    table.autocommit = False
    chain = iptc.Chain(table, 'POSTROUTING')
    for r in chain.rules:
        matches = r.matches
        matchesEntries = tuple(map(lambda m: (m.name, m.parameters), matches))
        matchDict = dict(matchesEntries)
        comment = matchDict.get('comment', None)
        if (comment is None):
            continue
        commentStr = comment.get('comment', '')
        if (not commentStr.startswith('docker_ipsec:')):
            continue
        chain.delete_rule(r)

def ipsec(*args, verbose=False):
    cmdLine = ['ipsec']
    cmdLine.extend(args)
        
    with tempfile.TemporaryFile() as outputFile:
        statusCode = subprocess.call(cmdLine, stdin=subprocess.DEVNULL, stdout=outputFile, stderr=outputFile)
        if (verbose or statusCode != 0):
            print(json.dumps({'verbose' : verbose, 'statusCode' : statusCode}, indent=2))
            outputFile.seek(0)
            outputStr = outputFile.read()
            print(outputStr)
        return statusCode == 0




# sudo iptables -j SNAT -t nat -I POSTROUTING 1 -o eth0 -d 172.31.0.0/16 -s 172.17.0.0/16 --to-source 172.15.15.4

    

