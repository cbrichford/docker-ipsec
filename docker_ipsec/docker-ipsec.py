#!/usr/bin/env python3


from docker_ipsec import DockerIPSecError
from docker_ipsec import ip_network_for_docker_network
from docker_ipsec import interface_name_for_index
from docker_ipsec import ipsec
from docker_ipsec import IPSecInfo
from docker_ipsec import IPSecInfoEntry
from docker_ipsec import install_iptables_rule
from docker_ipsec import route_table_entry_matches_ipsec_connection
from docker_ipsec import comment_matches_ipsec_connection
from docker_ipsec import filter_iptables_rules
from docker_ipsec import remove_iptables_rules
import ipsecparse
import sys
from pyroute2.iproute import IPRoute
import iptc
import argparse
import functools
import docker
import netaddr


def load_ipsec_conf(parsed_args):
    try:
        with open(parsed_args.ipsecConf, 'rt') as ipsec_conf_file:
            ipsec_conf_str = ipsec_conf_file.read()
    except BaseException as e:
        raise DockerIPSecError('Failed to read: {0}'.format(parsed_args.ipsecConf)) from e
    try:
        return ipsecparse.loads(ipsec_conf_str)
    except BaseException as e:
        raise DockerIPSecError('Failed to parse: {0}'.format(parsed_args.ipsecConf)) from e


def load_ipsec_connection(parsed_args):
    ipsec_conf = load_ipsec_conf(parsed_args)
    connection_name = parsed_args.connection
    ipsec_connection = ipsec_conf.get(('conn', connection_name), None)
    if ipsec_connection is None:
        raise DockerIPSecError('Unable to find connection {0} in {1}'.format(connection_name,
                                                                             parsed_args.ipsecConf))
    ipsec_connection['name'] = connection_name
    return ipsec_connection


def detect_connection_name(parsed_args, ipsec_conf):
    ipsec_connection_name = parsed_args.connection
    if ipsec_connection_name is not None:
        return ipsec_connection_name

    connection_entries = map(lambda e: (e[0][0], e[1]),
                             filter(lambda e: e[0][0] == 'conn' and e[0][1] != '%default',
                                    ipsec_conf.entries()))
    connections = dict(connection_entries)
    if len(connections) != 1:
        message_lines = ['IPSec configuration in {0} contains more than one connection, specify which one:'.format(parsed_args.ipsecConf)]
        message_lines.extend(connections.keys())
        message = '\n'.join(message_lines)
        raise DockerIPSecError(message)
    return tuple(connections.keys())[0]


def ipsec_route_to_rule(ip_network: netaddr.IPNetwork, ip_route: IPRoute, e: IPSecInfoEntry):
    ouptut_interface_index = e.output_interface_index()
    output_interface = interface_name_for_index(ouptut_interface_index, ip_route=ip_route)
    ip_network_cidr = '{0}/{1}'.format(ip_network.ip, ip_network.prefixlen)
    return e.source_ip(), output_interface, e.destination_cidr(), ip_network_cidr


def add_ip_networks(ip_route: IPRoute, ip_networks, ipsec_connection_name):
    ipsec_info = IPSecInfo(ip_route=ip_route)
    ipsec_entries = ipsec_info.entries()
    rules = []

    table = iptc.Table(iptc.Table.NAT)
    table.autocommit = False
    chain = iptc.Chain(table, 'POSTROUTING')

    filter_func = functools.partial(comment_matches_ipsec_connection, ipsec_connection_name)
    existing_rules = filter_iptables_rules(chain, filter_func)
    existing_rules_sources = set(map(lambda er: netaddr.IPNetwork(er.src), existing_rules))

    for network in ip_networks:
        if network in existing_rules_sources:
            continue
        route_to_rule = functools.partial(ipsec_route_to_rule, network, ip_route)
        rules.extend(map(route_to_rule, ipsec_entries))
    if len(rules) > 0:
        for rule in rules:
            install_iptables_rule(table, ipsec_connection_name, *rule)
        table.commit()


def get_ipsec_connection_routes(ipsec_info: IPSecInfo,
                                ipsec_connection):
    filter_func = functools.partial(route_table_entry_matches_ipsec_connection,
                                    ipsec_connection)
    return tuple(filter(filter_func, ipsec_info.entries()))


def is_connection_up(ip_route: IPRoute,
                     ipsec_connection):
    ipsec_info = IPSecInfo(ip_route=ip_route)
    routes = get_ipsec_connection_routes(ipsec_info, ipsec_connection)
    return len(routes) > 0


def connection_up(parsed_args):
    ipsec_connection = load_ipsec_connection(parsed_args)
    connection_name = ipsec_connection['name']
    docker_networks = parsed_args.dockerNetworks
    if len(docker_networks) > 0:
        docker_client = docker.DockerClient()
        docker_network_to_ip_network = functools.partial(ip_network_for_docker_network, docker_client)
        docker_ip_networks = tuple(map(docker_network_to_ip_network, docker_networks))
    else:
        docker_ip_networks = tuple()

    ip_route = IPRoute()
    if not is_connection_up(ip_route, ipsec_connection):
        ipsec_result = ipsec('up', connection_name)
        if ipsec_result.status != 0:
            raise DockerIPSecError('Failed to connect VPN: {0}\n{1}'.format(connection_name, ipsec_result.output))

    add_ip_networks(ip_route, docker_ip_networks, connection_name)


def connection_down(parsed_args):
    ipsec_connection = load_ipsec_connection(parsed_args)
    connection_name = ipsec_connection['name']
    ip_route = IPRoute()
    if is_connection_up(ip_route, ipsec_connection):
        ipsec_result = ipsec('down', connection_name)
        if ipsec_result.status != 0:
            raise DockerIPSecError('Failed to disconnect VPN: {0}\n{1}'.format(connection_name, ipsec_result.output))

    filter_func = functools.partial(comment_matches_ipsec_connection, connection_name)
    remove_iptables_rules(filter_func)


def add_docker_networks(parsed_args):
    ipsec_connection = load_ipsec_connection(parsed_args)
    connection_name = ipsec_connection['name']
    docker_networks = parsed_args.dockerNetworks

    docker_client = docker.DockerClient()
    docker_network_to_ip_network = functools.partial(ip_network_for_docker_network, docker_client)
    docker_ip_networks = tuple(map(docker_network_to_ip_network, docker_networks))
    ip_route = IPRoute()
    if not is_connection_up(ip_route, ipsec_connection):
        raise DockerIPSecError('IPSec connection {0} is not connected!'.format(connection_name))

    add_ip_networks(ip_route, docker_ip_networks, connection_name)


def remove_docker_networks(parsed_args):
    docker_networks = parsed_args.dockerNetworks
    docker_client = docker.DockerClient()
    docker_network_to_ip_network = functools.partial(ip_network_for_docker_network, docker_client)
    docker_ip_networks = set(map(docker_network_to_ip_network, docker_networks))

    def filter_func(comment):
        src_cidr = comment.get('srcCIDR', None)
        if src_cidr is None:
            return False
        src_network = netaddr.IPNetwork(src_cidr)
        return src_network in docker_ip_networks
    remove_iptables_rules(filter_func=filter_func)


def main():
    desc = 'Start and stop IPSec tunnels while allowing docker containers to route traffic down the tunnels'
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--ipsec-route-table', dest='ipsecRouteTable', type=int, default=220,
                        help='Route table containing IPSec routes')
    parser.add_argument('--ipsec-conf', dest='ipsecConf', type=str, default='/etc/ipsec.conf',
                        help='IPSec configuration file')

    sub_parsers = parser.add_subparsers(dest='command')

    up_parser = sub_parsers.add_parser('up', help='Start specified vpn connection.')
    up_parser.add_argument('connection',
                           type=str,
                           help='IPSec connection to bring up.')
    up_parser.add_argument('-n',
                           '--docker-network',
                           dest='dockerNetworks',
                           action='append',
                           default=list(),
                           help='Docker network to connect to the VPN.')

    down_parser = sub_parsers.add_parser('down', help='Stop specified vpn connection.')
    down_parser.add_argument('connection', type=str)

    add_network_parser = sub_parsers.add_parser('add-network',
                                                help='Add iptables rules to route packets from docker network to vpn.')
    add_network_parser.add_argument('connection', type=str)
    add_network_parser.add_argument('dockerNetworks', nargs='+')

    remove_network_parser = sub_parsers.add_parser('remove-network',
                                                   help='Remove iptables rules that route packets from docker network to vpn.')
    remove_network_parser.add_argument('dockerNetworks', nargs='+')

    parsed_args = parser.parse_args()

    try:
        if parsed_args.command == 'up':
            connection_up(parsed_args)
        elif parsed_args.command == 'down':
            connection_down(parsed_args)
        elif parsed_args.command == 'add-network':
            add_docker_networks(parsed_args)
        elif parsed_args.command == 'remove-network':
            remove_docker_networks(parsed_args)
    except DockerIPSecError as e:
        print(e.args[0])

if __name__ == '__main__':
    sys.exit(main())




    

