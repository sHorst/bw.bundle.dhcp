from ipaddress import ip_address, ip_network

defaults = {
    'dhcp': {
        'authoritative': False,
        'bootp': False,
        'log': 'local7',

        'lease-time': 7200,
        'max-lease-time': 43200,

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
            #         'peer': 'secondary',  # if this is a node name, it will setup a new peer for us
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