from ipaddress import ip_address, ip_network

@metadata_processor
def add_apt_packages(metadata):
    if node.has_bundle("apt"):
        metadata.setdefault('apt', {})
        metadata['apt'].setdefault('packages', {})

        metadata['apt']['packages']['isc-dhcp-server'] = {'installed': True}

    return metadata, DONE

@metadata_processor
def insert_all_nodes(metadata):
    metadata.setdefault('dhcp', {})
    metadata['dhcp'].setdefault('hosts', {})

    hosts = []

    for node in sorted(repo.nodes, key=lambda x: x.name):
        if node.partial_metadata == {}:
            return metadata, RUN_ME_AGAIN

        hosts += [node, ]

    available_subnets = [ip_network(x) for x in metadata.get('dhcp', {}).get('subnets', {}).keys()]

    for host in hosts:
        for interface, interface_config in host.partial_metadata.get('interfaces', {}).items():
            # if 'mac' not in interface_config:
            #     continue

            if len(interface_config.get('ip_addresses', [])) == 0:
                continue

            netmask = interface_config.get('netmask', '255.255.255.255')
            ips = [ip_address(x) for x in interface_config['ip_addresses']]
            first = True
            for ip in ips:
                network = ip_network('{}/{}'.format(ip, netmask), False)
                mac = interface_config.get('mac', None)

                if network not in available_subnets:
                    continue

                if mac and first:
                    first = False
                    # make connection only for first ip
                    metadata['dhcp']['hosts'].setdefault("{}_{}".format(host.name, interface), {
                        'mac': mac,
                        'ip': ip,
                    })
                else:
                    # only reserve ip so it is not used by DHCP
                    metadata['dhcp']['hosts'].setdefault("{}_{}".format(host.name, interface), {
                        'ip': ip,
                    })

    return metadata, DONE
