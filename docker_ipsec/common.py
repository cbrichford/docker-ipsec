import docker
import pyroute2
import netaddr
import tempfile
import iptc
import json
import subprocess
import collections

def toJSON(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True)

COMMENT_PREFIX = 'docker_ipsec:'

class DockerIPSecError(RuntimeError):
    pass


class IPSecInfoEntry:
    def __init__(self, table_entry):
        attrs = dict(table_entry.get('attrs', []))
        if len(attrs) == 0:
            raise DockerIPSecError('Unable to get attrs from table entry: {0}'.format(toJSON(table_entry)))
        self.__dest = attrs.get('RTA_DST', None)
        if self.__dest is None:
            raise DockerIPSecError('Unable to get destination from table entry: {0}'.format(toJSON(table_entry)))
        
        self.__src = attrs.get('RTA_PREFSRC', None)
        if self.__src is None:
            raise DockerIPSecError('Unable to get source from table entry: {0}'.format(toJSON(table_entry)))

        self.__gateway = attrs.get('RTA_GATEWAY', None)
        if self.__gateway is None:
            raise DockerIPSecError('Unable to get gateway from table entry: {0}'.format(toJSON(table_entry)))

        self.__interfaceIndex = attrs.get('RTA_OIF', None)
        if self.__interfaceIndex is None:
            raise DockerIPSecError('Unable to get output interface from table entry: {0}'.format(table_entry))
        
        self.__destLen = table_entry.get('dst_len', None)
        if self.__destLen is None:
            raise DockerIPSecError('Unable to get destination mask')

    def destination_cidr(self):
        return '{0}/{1}'.format(self.__dest, self.__destLen)

    def output_interface_index(self):
        return self.__interfaceIndex

    def source_ip(self):
        return self.__src


class IPSecInfo:

    def __init__(self, ipsec_table_index=220, ip_route=None):
        ip_route = ip_route if ip_route is not None else pyroute2.IPRoute()

        routes = ip_route.get_routes(table=ipsec_table_index)
        self.__entries = tuple(map(IPSecInfoEntry, routes))

    def entries(self):
        return self.__entries


def route_table_entry_matches_ipsec_connection(ipsec_connection, entry:IPSecInfoEntry):
    right_subnet = ipsec_connection.get('rightsubnet', None)
    if right_subnet is None:
        raise DockerIPSecError('Unable to determine rightsubnet for connection: {0}'.format(toJSON(ipsec_connection)))
    right_ip_network = netaddr.IPNetwork(right_subnet)
    entry_dest_ip_network = netaddr.IPNetwork(entry.destination_cidr())
    return right_ip_network == entry_dest_ip_network


def ip_network_for_docker_network(client: docker.DockerClient,
                                  network_name: str):
    networks = client.networks.list(names=[network_name])
    networks_count = len(networks)
    if networks_count == 0:
        raise DockerIPSecError('a Docker network not found: {0}'.format(network_name))
    if networks_count > 1:
        names = map(lambda n: n['Name'], networks)
        raise DockerIPSecError('More than one docker network found:\n{0}'.format('\n'.join(names)))
    network = networks[0]
    if network.name != network_name:
        raise DockerIPSecError('b Docker network not found: {0}'.format(network_name))
    network_id = network.id
    ipam = network.attrs.get('IPAM', None)
    if not isinstance(ipam, dict):
        raise DockerIPSecError('Docker network does not contain IPAM info:{0} ({1})'.format(network_name, network_id))
    ipam_configs = ipam.get('Config', None)
    if not isinstance(ipam_configs, list):
        raise DockerIPSecError('Docker network IPAM info does not contain Config: {0} ({1})'.format(network_name, network_id))
    ipam_config = ipam_configs[0]
    if not isinstance(ipam_config, dict):
        raise DockerIPSecError(
            'Docker network IPAM Config entry is not a dictionary: {0} ({1})'.format(network_name, network_id))
    subnet_str = ipam_config.get('Subnet', None)
    if not isinstance(subnet_str, str):
        raise DockerIPSecError('Docker network IPAM config does not contain Subnet: {0} ({1})'.format(network_name, network_id))

    gateway_str = ipam_config.get('Gateway', None)
    if not isinstance(gateway_str, str):
        raise DockerIPSecError('Docker network IPAM config does not contain Gateway: {0} ({1})'.format(network_name, network_id))

    return netaddr.IPNetwork(subnet_str).cidr


def interface_name_for_index(interface_index, ip_route=None):
    ip_route = ip_route if ip_route is not None else pyroute2.IPRoute()
    links = ip_route.get_links(interface_index)
    if len(links) != 1:
        raise DockerIPSecError('Expected one link for interface index, found {0}'.format(links))

    link = links[0]
    name = dict(link.get('attrs', [])).get('IFLA_IFNAME', None)
    if (name is None):
        raise DockerIPSecError('Unable to get interface name: {0}'.format(toJSON(links)))
    return name


def install_iptables_rule(table: iptc.Table,
                          ipsec_connection_name: str,
                          ipsec_virtual_ip: str,
                          output_interface: str,
                          destination_cidr: str,
                          src_cidr: str):
    rule = iptc.Rule()
    rule.out_interface = output_interface
    rule.src = src_cidr
    rule.dst = destination_cidr

    target = rule.create_target('SNAT')
    target.set_parameter('to-source', ipsec_virtual_ip)

    comment = rule.create_match('comment')
    comment_dict = {
        'vip': ipsec_virtual_ip,
        'destCIDR': destination_cidr,
        'srcCIDR': src_cidr,
        'connName': ipsec_connection_name
    }
    comment_str=json.dumps(comment_dict, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    comment.set_parameter('comment', '{}{}'.format(COMMENT_PREFIX, comment_str))
    chain = iptc.Chain(table, 'POSTROUTING')
    chain.insert_rule(rule)


def comment_matches_ip_network(ip_network: netaddr.IPNetwork, comment: dict):
    src_cidr = comment.get('srcCIDR', None)
    if src_cidr is None:
        return False
    src_network = netaddr.IPNetwork(src_cidr)
    return src_network == ip_network


def comment_matches_ipsec_connection(connection_name: str, comment: dict):
    rule_connection_name = comment.get('connName', None)
    if rule_connection_name is None:
        return False
    return rule_connection_name == connection_name


def filter_iptables_rules(iptables_chain: iptc.Chain,
                          filter_func):
    def _comment_filter(c):
        if c.startswith(COMMENT_PREFIX):
            try:
                return filter_func(json.loads(c[len(COMMENT_PREFIX):]))
            except ValueError:
                return False
        return False

    def _rule_filter(r):
        matches = r.matches
        matches_entries = tuple(map(lambda m: (m.name, m.get_all_parameters()), matches))
        match_dict = dict(matches_entries)
        comment = match_dict.get('comment', None)
        if comment is None:
            return False
        comment_values = comment.get('comment', '')
        matched_comments = tuple(filter(_comment_filter, comment_values))
        if len(matched_comments) == 0:
            return False
        return True

    return tuple(filter(_rule_filter, iptables_chain.rules))


def remove_iptables_rules(filter_func=None):
    table = iptc.Table(iptc.Table.NAT)
    table.autocommit = False
    chain = iptc.Chain(table, 'POSTROUTING')
    if filter_func is None:
        filter_func = lambda _: True
    rules_to_delete = filter_iptables_rules(chain, filter_func=filter_func)
    for r in rules_to_delete:
        chain.delete_rule(r)
    table.commit()


IPSecResult = collections.namedtuple('IPSecResult', ['status', 'output'])


def ipsec(*args) -> IPSecResult:
    cmd_line = ['ipsec']
    cmd_line.extend(args)
        
    with tempfile.TemporaryFile() as output_file:
        status_code = subprocess.call(cmd_line, stdin=subprocess.DEVNULL, stdout=output_file, stderr=output_file)
        output_file.seek(0)
        output = output_file.read().decode("utf-8", "strict")
        return IPSecResult(status=status_code, output=output)
    

