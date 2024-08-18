from ipaddress import ip_address, ip_network
from bundlewrap.metadata import DoNotRunAgain
from bundlewrap.exceptions import BundleError

defaults = {
    'dhcp': {
        'authoritative': False,
        # 'bootp': False,
        # 'log': 'local7',

        'lease-time': 7200,
        'max-lease-time': 43200,
        'tls': {
            # "trust-anchor": "kea_CA.pem",  # CA used to validate client certificates
            # "cert-file": "dhcp1_cert.pem",  # our Certificate
            # "key-file": "dhcp1_key.pem",  # our privateKey
        },

        'control_agent': {
            'enabled': False,
            # 'interface': 'main_interface',  # if not set, use host to set bind ip
            'host': '127.0.0.1',  # will be set by interface automaticaly
            'port': 8000,

            "tls-cert-required": False,  # Client needs to authenticate
        },

        'high_availability': {
            "mode": "off",  # can be off, load-balancing, hot-standby, passive-backup
            "client_name": None,  # will be autoset to node name
            "client_role": None,  # must be one of primary, secondary (only in load-balance), standby (only in hot-standby) or backup
            "heartbeat-delay": 10000,
            "max-response-delay": 60000,
            "max-ack-delay": 5000,
            "max-unacked-clients": 5,
            "max-rejected-lease-updates": 10,
            'can-auto-failover': True,  # this will be used to set in peer of other servers

            'peer_group': None,  # will automatically add all nodes with same peer group
            'peers': [
                # {
                #     'name': 'backup_server',
                #     'url': "https://192.168.2.123",
                #     'role': 'backup',
                #     'auto-failover': False,
                # },
            ],
        },

        'vendor_options': {
            # 'snom': {
            #     'tftp-server-name': {
            #         'code': 66,
            #         'type': 'text',
            #     },
            # },
        },

        'classes': {
            # 'snom': {
            #     'test': "substring(option[vendor-class-identifier],0,4) = 'snom'",
            #     'vendors': ['snom', ],
            #     'options': {
            #         'tftp-server-name': '"tftp://192.168.0.1"',
            #         'snom.tftp-server-name': '"tftp://192.168.0.1"',
            #         'ntp-servers': '192.168.0.1',
            #         'bootfile-name': 'concat("snom/",option vendor-class-identifier,".htm")',
            #         'snom.bootfile-name': 'concat("snom/",option vendor-class-identifier,".htm")',
            #     },
            #     'next-server': '192.168.0.1',
            #     'boot-file-name': "snom/snom370.cfg"',
            # },
        },

        'subnets': {
            # '192.168.0.0/24': {
            #     'range': ['192.168.0.100', '192.168.0.190'],
            #     'options': {
            #         'routers': '192.168.0.1',
            #         'broadcast-address': '192.168.0.255',
            #         'domain-name': 'home',
            #         'domain-name-servers': '192.168.0.1',
            #     },
            #     'failover': {
            #         'peers': ['secondary', ],  # if this is a node name, it will setup a new peer for us
            #     },
            # },
        },

        'hosts': {
            # 'host1': {
            #     'mac': '00:23:32:xx:xx:xx',
            #     'ip': '192.168.0.2',
            #     'options': {
            #         'host-name': '"host1"',
            #     }
            # },
        },
    }
}

if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {
            'isc-dhcp-server': {'installed': False},  # remove old server
            'kea': {'installed': True},
        }
    }


@metadata_reactor
def insert_all_nodes(metadata):
    hosts = []

    for node in sorted(repo.nodes, key=lambda x: x.name):
        if node.partial_metadata == {}:
            return {}

        hosts += [node, ]

    available_subnets = []
    for interface, interface_config in metadata.get('interfaces', {}).items():
        subnet_config = interface_config.get('isc-dhcp', None)
        if not subnet_config:
            continue

        available_subnets += [ip_network('{}/{}'.format(interface_config.get('ip_addresses', [None])[0], interface_config.get('netmask', '255.255.255.0')), strict=False), ]

    meta_hosts = {}
    for host in hosts:
        for interface, interface_config in host.partial_metadata.get('interfaces', {}).items():
            # if 'mac' not in interface_config:
            #     continue

            if len(interface_config.get('ip_addresses', [])) == 0:
                continue

            netmask = interface_config.get('netmask', '255.255.255.255')
            ips = [ip_address(x) for x in interface_config['ip_addresses']]
            gateway = interface_config.get('gateway', None)
            first = True
            for ip in ips:
                network = ip_network('{}/{}'.format(ip, netmask), False)
                mac = interface_config.get('mac', None)

                if network not in available_subnets:
                    continue

                if mac and first:
                    first = False
                    # make connection only for first ip
                    meta_hosts.setdefault("{}_{}".format(host.name, interface), {
                        'mac': mac,
                        'ip': str(ip),
                    })
                else:
                    # only reserve ip so it is not used by DHCP
                    meta_hosts.setdefault("{}_{}".format(host.name, interface), {
                        'ip': str(ip),
                    })

                if gateway:
                    meta_hosts["{}_{}".format(host.name, interface)].setdefault('options', {
                        'routers': gateway,
                    })

    return {
        'dhcp': {
            'hosts': meta_hosts,
        }
    }


@metadata_reactor
def convert_client_class_match_to_test(metadata):
    new_tests = {}

    for class_name, class_config in metadata.get('dhcp/classes', {}).items():
        old_match = class_config.get('match', None)
        if old_match is None:
            continue

        new_test = (old_match.replace('"', "'").replace('option vendor-class-identifier', 'option[60].hex').
                    replace('=', '==').replace('if ', '').replace('substring (', 'substring('))

        new_tests[class_name] = {
            'test': new_test
        }

    return {
        'dhcp': {
            'classes': new_tests,
        }
    }


@metadata_reactor
def set_ca_ip_for_interface(metadata):
    i = metadata.get('dhcp/control_agent/interface', None)

    if i == 'main_interface':
        i = metadata.get('main_interface', None)

    if i is None:
        raise DoNotRunAgain

    if i == 'all':
        ip = '0.0.0.0'
    else:
        interface_config = metadata.get(f'interfaces/{i}', {})
        if interface_config == {}:
            raise BundleError(f'Unknown interface {i}')

        ip = interface_config.get('ip_addresses', [None])[0]  # only get first ip

        if ip is None:
            raise BundleError(f'No IP for interface {i}')

    return {
        'dhcp': {
            'control_agent': {
                'host': ip,
            }
        }
    }


@metadata_reactor
def find_ha_peers(metadata):
    peer_group = metadata.get('dhcp/high_availability/peer_group')
    if (metadata.get('dhcp/high_availability/mode', 'off') == 'off' or
            peer_group is None):
        raise DoNotRunAgain

    peers = []
    iptables_rules = {}
    for peer in sorted(repo.nodes, key=lambda x: x.name):
        if peer.partial_metadata == {}:
            return {}

        if (peer.partial_metadata.get('dhcp/high_availability/mode', 'off') == 'off' or
                peer.partial_metadata.get('dhcp/high_availability/peer_group') != peer_group):
            continue

        peer_name = peer.partial_metadata.get('dhcp/high_availability/client_name', None)
        if peer_name is None:
            peer_name = peer.name

        host = peer.partial_metadata.get('dhcp/control_agent/host')
        port = peer.partial_metadata.get('dhcp/control_agent/port')
        tls = peer.partial_metadata.get('dhcp/tls/trust-anchor', None) is not None

        url = ('https' if tls else 'http') + f'://{host}:{port}'

        peers += [
            {
                'name': peer_name,
                'url': url,
                'role': peer.partial_metadata.get('dhcp/high_availability/client_role'),
                'auto-failover': peer.partial_metadata.get('dhcp/high_availability/can-auto-failover'),
            }
        ]

        if node.has_bundle("iptables") and node.name != peer.name:
            iptables_rules += repo.libs.iptables.accept(). \
                input(metadata.get('dhcp/control_agent/interface', 'main-interface')). \
                source(host). \
                state_new(). \
                tcp(). \
                dest_port(metadata.get('dhcp/control_agent/port'))

    return {
        'iptables': iptables_rules['iptables'],
        'dhcp': {
            'high_availability': {
                'peers': peers,
            }
        }
    }
