from ipaddress import ip_network, ip_address


def sort_hosts(x):
    if 'ip' in x[1]:
        return ip_address(x[1]['ip'])
    return ip_address(0)


def sort_subnets(x):
    if 'ip' in x[1]:
        return ip_address(x[1]['ip'])
    return 0


dhcp_config = node.metadata.get('dhcp', {})

svc_systemv = {}
svc_systemd = {}
restart_action = ''

if node.os == 'debian':
    if node.os_version[0] >= 9:
        svc_systemd["isc-dhcp-server"] = {
            'needs': ['pkg_apt:isc-dhcp-server'],
        }

        restart_action = 'svc_systemd:isc-dhcp-server:restart'
    else:
        svc_systemv["isc-dhcp-server"] = {
            'needs': ['pkg_apt:isc-dhcp-server'],
        }
        restart_action = 'svc_systemv:isc-dhcp-server:restart'

dhcp_config_file = [
    '# Config file dhcp',
    '#',
    'ddns-update-style none;',
]

if dhcp_config.get('authoritative', False):
    dhcp_config_file += [
        'authoritative;',
    ]

if dhcp_config.get('bootp', False):
    dhcp_config_file += [
        'allow bootp;',
        'allow booting;',
    ]


dhcp_config_file += [
    'log-facility {};'.format(dhcp_config.get('log', 'local7')),
    'default-lease-time {};'.format(dhcp_config.get('lease-time', 7200)),
    'max-lease-time {};'.format(dhcp_config.get('max-lease-time', 43200)),
]

# --------------------------------------
# define new vendor options
# --------------------------------------

for vendor, vendor_options in sorted(dhcp_config.get('vendor_options', {}).items(), key=lambda x: x[0]):
    dhcp_config_file += [
        'option space {};'.format(vendor),
    ]

    for option, option_config in sorted(vendor_options.items(), key=lambda x: x[1].get('code', 1)):
        dhcp_config_file += [
            'option {vendor}.{option} code {code} = {type};'.format(
                vendor=vendor,
                option=option,
                code=option_config['code'],
                type=option_config.get('type', 'text')
            )
        ]

# --------------------------------------
# define new classes
# --------------------------------------
for class_name, class_config in sorted(dhcp_config.get('classes', {}).items(), key=lambda x: x[0]):
    dhcp_config_file += [
        'class "{}" {{'.format(class_name),
        '    match {};'.format(class_config['match']),
    ]

    for vendor in sorted(class_config.get('vendors', [])):
        dhcp_config_file += [
            '    vendor-option-space {};'.format(vendor),
        ]

    for option, option_value in sorted(class_config.get('options', {}).items(), key=lambda x: x[0]):
        dhcp_config_file += [
            '    option {} {};'.format(option, option_value),
        ]

    dhcp_config_file += map(lambda x: "    " + x, class_config.get('add_raw_parameter', []))

    dhcp_config_file += [
        '}',
    ]

used_macs = []
used_ips = []
# --------------------------------------
# hosts
# --------------------------------------
for host, host_config in sorted(dhcp_config.get('hosts', {}).items(), key=sort_hosts):
    dhcp_config_file += [
        'host {} {{'.format(host),
    ]
    if 'mac' in host_config:
        mac = host_config['mac']
        if mac in used_macs:
            raise ValueError('mac {} is used twice'.format(mac))

        used_macs += [mac, ]
        dhcp_config_file += [
            '    hardware ethernet {};'.format(mac),
        ]
    if 'ip' in host_config:
        ip = host_config['ip']
        if ip in used_ips:
            raise ValueError('IP {} is used twice'.format(ip))

        used_ips += [ip, ]
        dhcp_config_file += [
            '    fixed-address {};'.format(ip),
        ]

    if 'filename' in host_config:
        dhcp_config_file += [
            '    filename {};'.format(host_config['filename']),
        ]

    if 'next-server' in host_config:
        dhcp_config_file += [
            '    next-server {};'.format(host_config['next-server']),
        ]

    for option, option_value in sorted(host_config.get('options', {}).items(), key=lambda x: x[0]):
        dhcp_config_file += [
            '    option {} {};'.format(option, option_value),
        ]

    dhcp_config_file += [
        '}',
    ]

interfaces = []
for interface, interface_config in node.metadata.get('interfaces', {}).items():
    subnet_config = interface_config.get('isc-dhcp', None)
    if not subnet_config:
        continue

    interfaces += [interface, ]

    subnet = ip_network('{}/{}'.format(interface_config.get('ip_addresses', [None])[0], interface_config.get('netmask', '255.255.255.0')), strict=False)
    network_addr = subnet.network_address
    netmask = subnet.netmask

    dhcp_config_file += [
        'subnet {} netmask {} {{'.format(network_addr, netmask),
    ]

    dhcp_config_file += [
        '    range {range[0]} {range[1]};'.format(
            range=subnet_config.get('range', [subnet.network_address, subnet.broadcast_address])
        ),
        '    option broadcast-address {};'.format(subnet.broadcast_address),
    ]

    for option, option_value in sorted(subnet_config.get('options', {}).items(), key=lambda x: x[0]):
        if option == 'broadcast-address':
            continue

        dhcp_config_file += [
            '    option {} {};'.format(option, option_value),
        ]

    for action in ['commit', 'release', 'expiry']:
        if action in subnet_config.get('on', {}):
            dhcp_config_file += [
                '    on {} {{'.format(action),
            ]

            dhcp_config_file += map(lambda x: (" " * 8) + x, subnet_config['on'][action])

            dhcp_config_file += [
                '    }',
            ]

    dhcp_config_file += [
        '}',
    ]


defaults = [
    '# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)',
    '',
    '# Path to dhcpd\'s config file (default: /etc/dhcp/dhcpd.conf).',
    '#DHCPDv4_CONF=/etc/dhcp/dhcpd.conf',
    '#DHCPDv6_CONF=/etc/dhcp/dhcpd6.conf',
    '',
    '# Path to dhcpd\'s PID file (default: /var/run/dhcpd.pid).',
    '#DHCPDv4_PID=/var/run/dhcpd.pid',
    '#DHCPDv6_PID=/var/run/dhcpd6.pid',
    '',
    '# Additional options to start dhcpd with.',
    '#       Don\'t use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead',
    '#OPTIONS=""',
    '',
    '# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?',
    '#       Separate multiple interfaces with spaces, e.g. "eth0 eth1".',
    'INTERFACESv4="{}"'.format(' '.join(interfaces)),
    'INTERFACESv6=""',
]

files = {
    '/etc/dhcp/dhcpd.conf': {
        'content': "\n".join(dhcp_config_file) + '\n',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'triggers': [
            restart_action,
        ],
    },
    '/etc/default/isc-dhcp-server': {
        'content': "\n".join(defaults) + '\n',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'triggers': [
            restart_action,
        ],
    },
}

symlinks = {
    '/etc/dhcp/dhcpd.leases': {
        'target': '/var/lib/dhcp/dhcpd.leases',
        'owner': 'root',
        'group': 'root',
        'needs': [
            'pkg_apt:isc-dhcp-server',
        ],
    }
}
