from ipaddress import ip_address, ip_network

defaults = {
    'dhcp': {
        'hosts': {},
    }
}

if node.has_bundle("apt"):
    defaults['apt'] = {
        'packages': {
            'isc-dhcp-server': {'installed': True}
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
