from ipaddress import ip_network, ip_address
from bundlewrap.exceptions import BundleError
from os.path import join
from bundlewrap.utils import get_file_contents

if node.os == 'debian' and node.os_version[0] < 12:
    raise BundleError('Bundle only supports debian > 12')


def sort_hosts(x):
    if 'ip' in x[1]:
        return ip_address(x[1]['ip'])
    return ip_address(0)


def sort_subnets(x):
    if 'ip' in x[1]:
        return ip_address(x[1]['ip'])
    return 0


def format_config(config, indent=0):
    out = ''
    if isinstance(config, dict):
        if len(config) == 0:
            return "{}"
        if len(config) == 1 and not isinstance(list(config.values())[0], dict) and not isinstance(list(config.values())[0], list):
            return "{ " + '"' + list(config.keys())[0] + '": ' + format_config(list(config.values())[0], indent + 1) + " }"

        out += "{\n"
        for key, value in config.items():
            out += "    " * indent + f'"{key}": ' + format_config(value, indent + 1) + ",\n"
        # delete last ,
        if len(out) > 2:
            out = out[:-2] + "\n"
        out += "    " * (indent - 1) + "}"
        return out
    elif isinstance(config, list):
        if len(config) == 0:
            return "[]"
        if len(config) == 1 and not isinstance(config[0], dict) and not isinstance(config[0], list):
            return "[ " + format_config(config[0], indent + 1) + " ]"

        out += "[\n"
        for value in config:
            out += "    " * indent + format_config(value, indent + 1) + ",\n"
        # delete last ,
        if len(out) > 2:
            out = out[:-2] + "\n"
        out += "    " * (indent - 1) + "]"
        return out
    elif isinstance(config, bool):
        return 'true' if config else 'false'
    elif isinstance(config, str):
        config = config.replace('"', "'")
        return f'"{config}"'
    elif isinstance(config, int):
        return f'{config}'

    return '"' + str(config) + '"'


def map_option_types(old_type):
    type_map = {
        'ip-address': 'ipv4-address',
        'unsigned integer 16': 'uint16',
        'text': 'string',
    }

    if old_type.startswith('array of '):
        return type_map.get(old_type[9:], old_type[9:]), 'array'
    elif old_type.startswith('encapsulate '):
        return type_map.get(old_type[12:], old_type[12:]), 'encapsulate'

    return type_map.get(old_type, old_type), None


dhcp_config = node.metadata.get('dhcp', {})
ca_config = dhcp_config.get('control_agent')
ha_config = dhcp_config.get('high_availability')

svc_systemd = {
    "kea-ctrl-agent.service": {
        'enabled': ca_config.get('enabled'),
        'running': ca_config.get('enabled'),
        'needs': ['pkg_apt:kea'],
    },
    "kea-dhcp4-server.service": {
        'needs': ['pkg_apt:kea'],
    },
    "kea-dhcp6-server.service": {
        'needs': ['pkg_apt:kea'],
    },
    "kea-dhcp-ddns-server.service": {
        'needs': ['pkg_apt:kea'],
    }
}

option_def = []
map_option_to_code = {
    'time-offset': 2,
    'routers': 3,
    'time-servers': 4,
    'name-servers': 5,
    'domain-name-servers': 6,
    'log-servers': 7,
    'cookie-servers': 8,
    'lpr-servers': 9,
    'impress-servers': 10,
    'resource-location-servers': 11,
    'boot-size': 13,
    'merit-dump': 14,
    'domain-name': 15,
    'swap-server': 16,
    'root-path': 17,
    'extensions-path': 18,
    'ip-forwarding': 19,
    'non-local-source-routing': 20,
    'policy-filter': 21,
    'max-dgram-reassembly': 22,
    'default-ip-ttl': 23,
    'path-mtu-aging-timeout': 24,
    'path-mtu-plateau-table': 25,
    'interface-mtu': 26,
    'all-subnets-local': 27,
    'broadcast-address': 28,
    'perform-mask-discovery': 29,
    'mask-supplier': 30,
    'router-discovery': 31,
    'router-solicitation-address': 32,
    'static-routes': 33,
    'trailer-encapsulation': 34,
    'arp-cache-timeout': 35,
    'ieee802-3-encapsulation': 36,
    'default-tcp-ttl': 37,
    'tcp-keepalive-interval': 38,
    'tcp-keepalive-garbage': 39,
    'nis-domain': 40,
    'nis-servers': 41,
    'ntp-servers': 42,
    'vendor-encapsulated-options': 43,
    'netbios-name-servers': 44,
    'netbios-dd-server': 45,
    'netbios-node-type': 46,
    'netbios-scope': 47,
    'font-servers': 48,
    'x-display-manager': 49,
    'dhcp-option-overload': 52,
    'dhcp-server-identifier': 54,
    'dhcp-message': 56,
    'dhcp-max-message-size': 57,
    'vendor-class-identifier': 60,
    'nwip-domain-name': 62,
    'nwip-suboptions': 63,
    'nisplus-domain-name': 64,
    'nisplus-servers': 65,
    'tftp-server-name': 66,
    'boot-file-name': 67,
    'mobile-ip-home-agent': 68,
    'smtp-server': 69,
    'pop-server': 70,
    'nntp-server': 71,
    'www-server': 72,
    'finger-server': 73,
    'irc-server': 74,
    'streettalk-server': 75,
    'streettalk-directory-assistance-server': 76,
    'user-class': 77,
    'slp-directory-agent': 78,
    'slp-service-scope': 79,
    'nds-server': 85,
    'nds-tree-name': 86,
    'nds-context': 87,
    'bcms-controller-names': 88,
    'bcms-controller-address': 89,
    'client-system': 93,
    'client-ndi': 94,
    'uuid-guid': 97,
    'uap-servers': 98,
    'geoconf-civic': 99,
    'pcode': 100,
    'tcode': 101,
    'v6-only-preferred': 108,
    'netinfo-server-address': 112,
    'netinfo-server-tag': 113,
    'default-url': 114,
    'auto-config': 116,
    'name-service-search': 117,
    'domain-search': 119,
    'vivco-suboptions': 124,
    'vivso-suboptions': 125,
    'pana-agent': 136,
    'v4-lost': 137,
    'capwap-ac-v4': 138,
    'sip-ua-cs-domains': 141,
    'rdnss-selection': 146,
    'v4-portparams': 159,
    'v4-captive-portal': 160,
    'option-6rd': 212,
    'v4-access-domain': 213,
    'subnet-mask': 1,
    'host-name': 12,
    'dhcp-requested-address': 50,
    'dhcp-lease-time': 51,
    'dhcp-message-type': 53,
    'dhcp-parameter-request-list': 55,
    'dhcp-renewal-time': 58,
    'dhcp-rebinding-time': 59,
    'dhcp-client-identifier': 61,
    'fqdn': 81,
    'dhcp-agent-options': 82,
    'authenticate': 90,
    'client-last-transaction-time': 91,
    'associated-ip': 92,
    'subnet-selection': 118,
}

# --------------------------------------
# define new vendor options
# --------------------------------------
for vendor, vendor_options in sorted(dhcp_config.get('vendor_options', {}).items(), key=lambda x: x[0]):
    for option, option_config in sorted(vendor_options.items(), key=lambda x: x[1].get('code', 1)):
        (new_type, special_type) = map_option_types(option_config.get('type', 'text'))
        op = {
            "space": vendor,
            "name": option,
            "code": option_config.get('code'),
        }

        map_option_to_code[f'{vendor}.{option}'] = option_config.get('code')

        if special_type == 'array':
            op['type'] = new_type
            op['array'] = True
        elif special_type == 'encapsulate':
            op['type'] = 'empty'
            op['encapsulate'] = new_type
        else:
            op['type'] = new_type

            # allow to set those fields
            if option_config.get('encapsulate', False):
                op['encapsulate'] = option_config.get('encapsulate')
            if option_config.get('array', False):
                op['array'] = option_config.get('array')

        option_def += [
            op,
        ]

# --------------------------------------
# define new classes
# --------------------------------------
client_classes = []
for class_name, class_config in sorted(dhcp_config.get('classes', {}).items(), key=lambda x: x[0]):
    vendor_option_def = []
    vendor_option_data = []

    # add vendor-encapsulated-options
    for vendor in sorted(class_config.get('vendors', [])):
        vendor_option_def += [
            {
                'name': 'vendor-encapsulated-options',
                'code': 43,
                'type': 'empty',
                'encapsulate': vendor,
            }
        ]

        vendor_option_data += [
            {
                "name": "vendor-encapsulated-options",
                "code": 43
            },
        ]

    for option, option_value in sorted(class_config.get('options', {}).items(), key=lambda x: x[0]):
        if '.' in option:
            space, name = option.split('.', 2)
        else:
            space = 'dhcp4'
            name = option

        vendor_option_data += [
            {
              'space': space,
              'name': name,
              'code': map_option_to_code.get(option, 0),
              'data': option_value
            },
        ]

    client_class = {
        'name': class_name,
        'test': class_config.get('test'),
    }

    if vendor_option_data:
        client_class['option-data'] = vendor_option_data

    if vendor_option_def:
        client_class['option-def'] = vendor_option_def

    # add fixed parameter
    for parameter in ['next-server', 'server-hostname', 'boot-file-name']:
        if class_config.get(parameter, False):
            client_class[parameter] = class_config.get(parameter)

    client_classes += [
        client_class,
    ]

used_macs = []
used_ips = []
reservations = {
    'global': [],
}
# --------------------------------------
# hosts
# --------------------------------------
for host, host_config in sorted(dhcp_config.get('hosts', {}).items(), key=sort_hosts):
    reservation = {
        'hostname': host,
    }
    subnet = None

    # we cannot make this host work
    if 'mac' not in host_config or 'ip' not in host_config:
        continue

    # find mac
    mac = host_config['mac'].lower()
    if mac in used_macs:
        raise ValueError('mac {} is used twice'.format(mac))

    used_macs += [mac, ]
    reservation['hw-address'] = mac

    # find ip
    ip = host_config['ip']
    if ip in used_ips:
        print(dhcp_config.get('hosts'))
        raise ValueError('IP {} is used twice'.format(ip))

    used_ips += [ip, ]

    net_cidr = host_config.get('net_cidr', 24)
    subnet = ip_network(f'{ip}/{net_cidr}', strict=False)
    reservation['ip-address'] = ip

    option_data = []
    if 'filename' in host_config:
        option_data += [
            {
                'space': 'dhcp4',
                'name': 'boot-file-name',
                'code': map_option_to_code.get('boot-file-name', 0),
                'data': host_config.get('filename')
            },
        ]

    if 'next-server' in host_config:
        option_data += [
            {
                'space': 'dhcp4',
                'name': 'next-server',
                'code': map_option_to_code.get('next-server', 0),
                'data': host_config.get('next-server')
            },
        ]

    for option, option_value in sorted(host_config.get('options', {}).items(), key=lambda x: x[0]):
        if '.' in option:
            space, name = option.split('.', 2)
        else:
            space = 'dhcp4'
            name = option

        option_data += [
            {
                'space': space,
                'name': name,
                'code': map_option_to_code.get(option, 0),
                'data': option_value
            },
        ]

    if option_data:
        reservation['option-data'] = option_data

    if reservation:
        if subnet:
            reservations.setdefault(str(subnet), [])
            reservations[str(subnet)] += [
                reservation,
            ]
        else:
            reservations['global'] += [
                reservation,
            ]


subnet4 = []
interfaces = []
# --------------------------------------
# subnets
# --------------------------------------
for interface, interface_config in node.metadata.get('interfaces', {}).items():
    subnet_config = interface_config.get('isc-dhcp', None)
    if not subnet_config:
        continue

    interfaces += [interface, ]

    subnet = ip_network('{}/{}'.format(interface_config.get('ip_addresses', [None])[0],
                                       interface_config.get('netmask', '255.255.255.0')), strict=False)
    pool = ' - '.join(subnet_config.get('range', [subnet.network_address, subnet.broadcast_address]))

    option_data = [
        {
            'space': 'dhcp4',
            'name': 'broadcast-address',
            'code': map_option_to_code.get('broadcast-address', 0),
            'data': subnet.broadcast_address
        },
    ]

    for option, option_value in sorted(subnet_config.get('options', {}).items(), key=lambda x: x[0]):
        if option == 'broadcast-address':
            continue

        if '.' in option:
            space, name = option.split('.', 2)
        else:
            space = 'dhcp4'
            name = option

        option_data += [
            {
                'space': space,
                'name': name,
                'code': map_option_to_code.get(option, 0),
                'data': option_value
            },
        ]

    # TODO: make these actions work again
    # for action in ['commit', 'release', 'expiry']:
    #     if action in subnet_config.get('on', {}):
    #         dhcp_config_file += [
    #             '    on {} {{'.format(action),
    #         ]
    #
    #         dhcp_config_file += map(lambda x: (" " * 8) + x, subnet_config['on'][action])
    #
    #         dhcp_config_file += [
    #             '    }',
    #         ]

    subnet_reservations = reservations.get(str(subnet), [])

    s = {
        'id': subnet_config.get('id'),
        'subnet': subnet,
        'interface': interface,
        'pools': [
            {'pool': pool, },
        ],
    }

    if option_data:
        s['option-data'] = option_data
    if subnet_reservations:
        s['reservations'] = subnet_reservations

    subnet4 += [
        s,
    ]


ctrl_agent = {
    # This is a basic configuration for the Kea Control Agent.
    # RESTful interface to be available at http:#127.0.0.1:8000/
    "Control-agent": {
        "http-host": ca_config.get('host'),
        # If enabling HA and multi-threading, the 8000 port is used by the HA
        # hook library http listener. When using HA hook library with
        # multi-threading to function, make sure the port used by dedicated
        # listener is different (e.g. 8001) than the one used by CA. Note
        # the commands should still be sent via CA. The dedicated listener
        # is specifically for HA updates only.
        "http-port": ca_config.get('port'),

        # Specify location of the files to which the Control Agent
        # should connect to forward commands to the DHCPv4, DHCPv6
        # and D2 servers via unix domain sockets.
        "control-sockets": {
            "dhcp4": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            },
            "dhcp6": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea6-ctrl-socket"
            },
            "d2": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea-ddns-ctrl-socket"
            }
        },

        # Specify hooks libraries that are attached to the Control Agent.
        # Such hooks libraries should support 'control_command_receive'
        # hook point. This is currently commented out because it has to
        # point to the existing hooks library. Otherwise the Control
        # Agent will fail to start.
        "hooks-libraries": [
            #  {
            #      "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/control-agent-commands.so",
            #      "parameters": {
            #          "param1": "foo"
            #      }
            #  }
        ],

        # Logging configuration starts here. Kea uses different loggers to log various
        # activities. For details (e.g. names of loggers), see Chapter 18.
        "loggers": [
            {
                # This specifies the logging for Control Agent daemon.
                "name": "kea-ctrl-agent",
                "output_options": [
                    {
                        # Specifies the output file. There are several special values
                        # supported:
                        # - stdout (prints on standard output)
                        # - stderr (prints on standard error)
                        # - syslog (logs to syslog)
                        # - syslog:name (logs to syslog using specified name)
                        # Any other value is considered a name of the file
                        "output": "stdout",

                        # Shorter log pattern suitable for use with systemd,
                        # avoids redundant information
                        "pattern": "%-5p %m\\n"

                        # This governs whether the log output is flushed to disk after
                        # every write.
                        # "flush": false,

                        # This specifies the maximum size of the file before it is
                        # rotated.
                        # "maxsize": 1048576,

                        # This specifies the maximum number of rotated files to keep.
                        # "maxver": 8
                    }
                ],
                # This specifies the severity of log messages to keep. Supported values
                # are: FATAL, ERROR, WARN, INFO, DEBUG
                "severity": "INFO",

                # If DEBUG level is specified, this value is used. 0 is least verbose,
                # 99 is most verbose. Be cautious, Kea can generate lots and lots
                # of logs if told to do so.
                "debuglevel": 0
            }
        ]
    }
}

all_set = True
tls_enabled = False
# add TLS to control_agent
for parameter in ['trust-anchor', 'cert-file', 'key-file']:
    filename = dhcp_config.get('tls').get(parameter, None)

    if filename is None:
        all_set = False
        continue

    tls_enabled = True

    ctrl_agent['Control-agent'][parameter] = join('/etc/kea/ssl', filename)

if tls_enabled and not all_set:
    raise BundleError('you need to set all or none of those paremeters: trust-anchor, cert-file, key-file')

# parameter makes only sense, if certs are set
if all_set:
    ctrl_agent['Control-agent']['cert-required'] = ca_config.get('tls-cert-required')

dhcp4 = {
    # DHCPv4 configuration starts here. This section will be read by DHCPv4 server
    # and will be ignored by other components.
    "Dhcp4": {
        "dhcp-ddns": {
            'enable-updates': False,
        },
        'authoritative': dhcp_config.get('authoritative'),

        # TODO: make this work again
        # if dhcp_config.get('bootp'):
        #     dhcp_config_file += [
        #         'allow bootp;',
        #         'allow booting;',
        #     ]

        # Add names of your network interfaces to listen on.
        "interfaces-config": {
            # See section 8.2.4 for more details. You probably want to add just
            # interface name (e.g. "eth0" or specific IPv4 address on that
            # interface name (e.g. "eth0/192.0.2.1").
            "interfaces": interfaces,

            # Kea DHCPv4 server by default listens using raw sockets. This ensures
            # all packets, including those sent by directly connected clients
            # that don't have IPv4 address yet, are received. However, if your
            # traffic is always relayed, it is often better to use regular
            # UDP sockets. If you want to do that, uncomment this line:
            # "dhcp-socket-type": "udp"
        },

        # Kea supports control channel, which is a way to receive management \
        # commands while the server is running. This is a Unix domain socket that
        # receives commands formatted in JSON, e.g. config-set (which sets new
        # configuration), config-reload (which tells Kea to reload its
        # configuration from file), statistic-get (to retrieve statistics) and many
        # more. For detailed description, see Sections 8.8, 16 and 15.
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/run/kea/kea4-ctrl-socket"
        },

        # Use Memfile lease database backend to store leases in a CSV file.
        # Depending on how Kea was compiled, it may also support SQL databases
        # (MySQL and/or PostgreSQL). Those database backends require more
        # parameters, like name, host and possibly user and password.
        # There are dedicated examples for each backend. See Section 7.2.2 "Lease
        # Storage" for details.
        "lease-database": {
            # Memfile is the simplest and easiest backend to use. It's an in-memory
            # C++ database that stores its state in CSV file.
            "type": "memfile",
            "lfc-interval": 3600
        },

        # Kea allows storing host reservations in a database. If your network is
        # small or you have few reservations, it's probably easier to keep them
        # in the configuration file. If your network is large, it's usually better
        # to use database for it. To enable it, uncomment the following:
        # "hosts-database": {
        #     "type": "mysql",
        #     "name": "kea",
        #     "user": "kea",
        #     "password": "kea",
        #     "host": "localhost",
        #     "port": 3306
        # },
        # See Section 7.2.3 "Hosts storage" for details.

        # Setup reclamation of the expired leases and leases affinity.
        # Expired leases will be reclaimed every 10 seconds. Every 25
        # seconds reclaimed leases, which have expired more than 3600
        # seconds ago, will be removed. The limits for leases reclamation
        # are 100 leases or 250 ms for a single cycle. A warning message
        # will be logged if there are still expired leases in the
        # database after 5 consecutive reclamation cycles.
        "expired-leases-processing": {
            "reclaim-timer-wait-time": 10,
            "flush-reclaimed-timer-wait-time": 25,
            "hold-reclaimed-time": 3600,
            "max-reclaim-leases": 100,
            "max-reclaim-time": 250,
            "unwarned-reclaim-cycles": 5
        },

        # Global timers specified here apply to all subnets, unless there are
        # subnet specific values defined in particular subnets.
        "renew-timer": 900,
        "rebind-timer": 1800,

        "valid-lifetime": dhcp_config.get('lease-time'),
        "max-valid-lifetime": dhcp_config.get('max-lease-time'),

        "option-def": option_def,
        # Many additional parameters can be specified here:
        # - option definitions (if you want to define vendor options, your own
        #                       custom options or perhaps handle standard options
        #                       that Kea does not support out of the box yet)
        # - client classes
        # - hooks
        # - ddns information (how the DHCPv4 component can reach a DDNS daemon)
        #
        # Some of them have examples below, but there are other parameters.
        # Consult Kea User's Guide to find out about them.

        # These are global options. They are going to be sent when a client
        # requests them, unless overwritten with values in more specific scopes.
        # The scope hierarchy is:
        # - global (most generic, can be overwritten by class, subnet or host)
        # - class (can be overwritten by subnet or host)
        # - subnet (can be overwritten by host)
        # - host (most specific, overwrites any other scopes)
        #
        # Not all of those options make sense. Please configure only those that
        # are actually useful in your network.
        #
        # For a complete list of options currently supported by Kea, see
        # Section 7.2.8 "Standard DHCPv4 Options". Kea also supports
        # vendor options (see Section 7.2.10) and allows users to define their
        # own custom options (see Section 7.2.9).
        "option-data": [],
        # [
        #     # When specifying options, you typically need to specify
        #     # one of (name or code) and data. The full option specification
        #     # covers name, code, space, csv-format and data.
        #     # space defaults to "dhcp4" which is usually correct, unless you
        #     # use encapsulate options. csv-format defaults to "true", so
        #     # this is also correct, unless you want to specify the whole
        #     # option value as long hex string. For example, to specify
        #     # domain-name-servers you could do this:
        #     # {
        #     #     "name": "domain-name-servers",
        #     #     "code": 6,
        #     #     "csv-format": "true",
        #     #     "space": "dhcp4",
        #     #     "data": "192.0.2.1, 192.0.2.2"
        #     # }
        #     # but it's a lot of writing, so it's easier to do this instead:
        #     {
        #         "name": "domain-name-servers",
        #         "data": "192.0.2.1, 192.0.2.2"
        #     },
        #
        #     # Typically people prefer to refer to options by their names, so they
        #     # don't need to remember the code names. However, some people like
        #     # to use numerical values. For example, option "domain-name" uses
        #     # option code 15, so you can reference to it either by
        #     # "name": "domain-name" or "code": 15.
        #     {
        #         "code": 15,
        #         "data": "example.org"
        #     },
        #
        #     # Domain search is also a popular option. It tells the client to
        #     # attempt to resolve names within those specified domains. For
        #     # example, name "foo" would be attempted to be resolved as
        #     # foo.mydomain.example.com and if it fails, then as foo.example.com
        #     {
        #         "name": "domain-search",
        #         "data": "mydomain.example.com, example.com"
        #     },
        #
        #     # String options that have a comma in their values need to have
        #     # it escaped (i.e. each comma is preceded by two backslashes).
        #     # That's because commas are reserved for separating fields in
        #     # compound options. At the same time, we need to be conformant
        #     # with JSON spec, that does not allow "\,". Therefore the
        #     # slightly uncommon double backslashes notation is needed.
        #
        #     # Legal JSON escapes are \ followed by "\/bfnrt character
        #     # or \u followed by 4 hexadecimal numbers (currently Kea
        #     # supports only \u0000 to \u00ff code points).
        #     # CSV processing translates '\\' into '\' and '\,' into ','
        #     # only so for instance '\x' is translated into '\x'. But
        #     # as it works on a JSON string value each of these '\'
        #     # characters must be doubled on JSON input.
        #     {
        #         "name": "boot-file-name",
        #         "data": "EST5EDT4\\,M3.2.0/02:00\\,M11.1.0/02:00"
        #     },
        #
        #     # Options that take integer values can either be specified in
        #     # dec or hex format. Hex format could be either plain (e.g. abcd)
        #     # or prefixed with 0x (e.g. 0xabcd).
        #     {
        #         "name": "default-ip-ttl",
        #         "data": "0xf0"
        #     }
        #
        #     # Note that Kea provides some of the options on its own. In particular,
        #     # it sends IP Address lease type (code 51, based on valid-lifetime
        #     # parameter, Subnet mask (code 1, based on subnet definition), Renewal
        #     # time (code 58, based on renew-timer parameter), Rebind time (code 59,
        #     # based on rebind-timer parameter).
        # ],

        # Other global parameters that can be defined here are option definitions
        # (this is useful if you want to use vendor options, your own custom
        # options or perhaps handle options that Kea does not handle out of the box
        # yet).

        # You can also define classes. If classes are defined, incoming packets
        # may be assigned to specific classes. A client class can represent any
        # group of devices that share some common characteristic, e.g. Windows
        # devices, iphones, broken printers that require special options, etc.
        # Based on the class information, you can then allow or reject clients
        # to use certain subnets, add special options for them or change values
        # of some fixed fields.
        "client-classes": client_classes,
        # [
        #     {
        #         # This specifies a name of this class. It's useful if you need to
        #         # reference this class.
        #         "name": "voip",
        #
        #         # This is a test. It is an expression that is being evaluated on
        #         # each incoming packet. It is supposed to evaluate to either
        #         # true or false. If it's true, the packet is added to specified
        #         # class. See Section 12 for a list of available expressions. There
        #         # are several dozens. Section 8.2.14 for more details for DHCPv4
        #         # classification and Section 9.2.19 for DHCPv6.
        #         "test": "substring(option[60].hex,0,6) == 'Aastra'",
        #
        #         # If a client belongs to this class, you can define extra behavior.
        #         # For example, certain fields in DHCPv4 packet will be set to
        #         # certain values.
        #         "next-server": "192.0.2.254",
        #         "server-hostname": "hal9000",
        #         "boot-file-name": "/dev/null"
        #
        #         # You can also define option values here if you want devices from
        #         # this class to receive special options.
        #     }
        # ],

        # Another thing possible here are hooks. Kea supports a powerful mechanism
        # that allows loading external libraries that can extract information and
        # even influence how the server processes packets. Those libraries include
        # additional forensic logging capabilities, ability to reserve hosts in
        # more flexible ways, and even add extra commands. For a list of available
        # hook libraries, see https:#gitlab.isc.org/isc-projects/kea/wikis/Hooks-available.
        # "hooks-libraries": [
        #   {
        #       # Forensic Logging library generates forensic type of audit trail
        #       # of all devices serviced by Kea, including their identifiers
        #       # (like MAC address), their location in the network, times
        #       # when they were active etc.
        #       "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_legal_log.so",
        #       "parameters": {
        #           "path": "/var/lib/kea",
        #           "base-name": "kea-forensic4"
        #       }
        #   },
        #   {
        #       # Flexible identifier (flex-id). Kea software provides a way to
        #       # handle host reservations that include addresses, prefixes,
        #       # options, client classes and other features. The reservation can
        #       # be based on hardware address, DUID, circuit-id or client-id in
        #       # DHCPv4 and using hardware address or DUID in DHCPv6. However,
        #       # there are sometimes scenario where the reservation is more
        #       # complex, e.g. uses other options that mentioned above, uses part
        #       # of specific options or perhaps even a combination of several
        #       # options and fields to uniquely identify a client. Those scenarios
        #       # are addressed by the Flexible Identifiers hook application.
        #       "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_flex_id.so",
        #       "parameters": {
        #           "identifier-expression": "relay4[2].hex"
        #       }
        #   }
        # ],

        "host-reservation-identifiers": [
            "hw-address"
        ],

        'reservations': reservations['global'],

        # Below an example of a simple IPv4 subnet declaration. Uncomment to enable
        # it. This is a list, denoted with [ ], of structures, each denoted with
        # { }. Each structure describes a single subnet and may have several
        # parameters. One of those parameters is "pools" that is also a list of
        # structures.
        "subnet4": subnet4,
        # [
        #     {
        #         # This defines the whole subnet. Kea will use this information to
        #         # determine where the clients are connected. This is the whole
        #         # subnet in your network. This is mandatory parameter for each
        #         # subnet.
        #         "subnet": "192.0.2.0/24",
        #
        #         # Pools define the actual part of your subnet that is governed
        #         # by Kea. Technically this is optional parameter, but it's
        #         # almost always needed for DHCP to do its job. If you omit it,
        #         # clients won't be able to get addresses, unless there are
        #         # host reservations defined for them.
        #         "pools": [ { "pool": "192.0.2.1 - 192.0.2.200" } ],
        #
        #         # These are options that are subnet specific. In most cases,
        #         # you need to define at least routers option, as without this
        #         # option your clients will not be able to reach their default
        #         # gateway and will not have Internet connectivity.
        #         "option-data": [
        #             {
        #                 # For each IPv4 subnet you most likely need to specify at
        #                 # least one router.
        #                 "name": "routers",
        #                 "data": "192.0.2.1"
        #             }
        #         ],
        #
        #         # Kea offers host reservations mechanism. Kea supports reservations
        #         # by several different types of identifiers: hw-address
        #         # (hardware/MAC address of the client), duid (DUID inserted by the
        #         # client), client-id (client identifier inserted by the client) and
        #         # circuit-id (circuit identifier inserted by the relay agent).
        #         #
        #         # Kea also support flexible identifier (flex-id), which lets you
        #         # specify an expression that is evaluated for each incoming packet.
        #         # Resulting value is then used for as an identifier.
        #         #
        #         # Note that reservations are subnet-specific in Kea. This is
        #         # different than ISC DHCP. Keep that in mind when migrating
        #         # your configurations.
        #         "reservations": [
        #
        #             # This is a reservation for a specific hardware/MAC address.
        #             # It's a rather simple reservation: just an address and nothing
        #             # else.
        #             {
        #                 "hw-address": "1a:1b:1c:1d:1e:1f",
        #                 "ip-address": "192.0.2.201"
        #             },
        #
        #             # This is a reservation for a specific client-id. It also shows
        #             # the this client will get a reserved hostname. A hostname can
        #             # be defined for any identifier type, not just client-id.
        #             {
        #                 "client-id": "01:11:22:33:44:55:66",
        #                 "ip-address": "192.0.2.202",
        #                 "hostname": "special-snowflake"
        #             },
        #
        #             # The third reservation is based on DUID. This reservation defines
        #             # a special option values for this particular client. If the
        #             # domain-name-servers option would have been defined on a global,
        #             # subnet or class level, the host specific values take preference.
        #             {
        #                 "duid": "01:02:03:04:05",
        #                 "ip-address": "192.0.2.203",
        #                 "option-data": [ {
        #                     "name": "domain-name-servers",
        #                     "data": "10.1.1.202, 10.1.1.203"
        #                 } ]
        #             },
        #
        #             # The fourth reservation is based on circuit-id. This is an option
        #             # inserted by the relay agent that forwards the packet from client
        #             # to the server.  In this example the host is also assigned vendor
        #             # specific options.
        #             #
        #             # When using reservations, it is useful to configure
        #             # reservations-global, reservations-in-subnet,
        #             # reservations-out-of-pool (subnet specific parameters)
        #             # and host-reservation-identifiers (global parameter).
        #             {
        #                 "client-id": "01:12:23:34:45:56:67",
        #                 "ip-address": "192.0.2.204",
        #                 "option-data": [
        #                     {
        #                         "name": "vivso-suboptions",
        #                         "data": "4491"
        #                     },
        #                     {
        #                         "name": "tftp-servers",
        #                         "space": "vendor-4491",
        #                         "data": "10.1.1.202, 10.1.1.203"
        #                     }
        #                 ]
        #             },
        #             # This reservation is for a client that needs specific DHCPv4
        #             # fields to be set. Three supported fields are next-server,
        #             # server-hostname and boot-file-name
        #             {
        #                 "client-id": "01:0a:0b:0c:0d:0e:0f",
        #                 "ip-address": "192.0.2.205",
        #                 "next-server": "192.0.2.1",
        #                 "server-hostname": "hal9000",
        #                 "boot-file-name": "/dev/null"
        #             },
        #             # This reservation is using flexible identifier. Instead of
        #             # relying on specific field, sysadmin can define an expression
        #             # similar to what is used for client classification,
        #             # e.g. substring(relay[0].option[17],0,6). Then, based on the
        #             # value of that expression for incoming packet, the reservation
        #             # is matched. Expression can be specified either as hex or
        #             # plain text using single quotes.
        #             #
        #             # Note: flexible identifier requires flex_id hook library to be
        #             # loaded to work.
        #             {
        #                 "flex-id": "'s0mEVaLue'",
        #                 "ip-address": "192.0.2.206"
        #             }
        #             # You can add more reservations here.
        #         ]
        #         # You can add more subnets there.
        #     }
        # ],

        # There are many, many more parameters that DHCPv4 server is able to use.
        # They were not added here to not overwhelm people with too much
        # information at once.

        # Logging configuration starts here. Kea uses different loggers to log various
        # activities. For details (e.g. names of loggers), see Chapter 18.
        "loggers": [
            {
                # This section affects kea-dhcp4, which is the base logger for DHCPv4
                # component. It tells DHCPv4 server to write all log messages (on
                # severity INFO or more) to a file.
                "name": "kea-dhcp4",
                "output_options": [
                    {
                        # Specifies the output file. There are several special values
                        # supported:
                        # - stdout (prints on standard output)
                        # - stderr (prints on standard error)
                        # - syslog (logs to syslog)
                        # - syslog:name (logs to syslog using specified name)
                        # Any other value is considered a name of the file
                        "output": "stdout",

                        # Shorter log pattern suitable for use with systemd,
                        # avoids redundant information
                        "pattern": "%-5p %m\\n",

                        # This governs whether the log output is flushed to disk after
                        # every write.
                        # "flush": false,

                        # This specifies the maximum size of the file before it is
                        # rotated.
                        # "maxsize": 1048576,

                        # This specifies the maximum number of rotated files to keep.
                        # "maxver": 8
                    }
                ],
                # This specifies the severity of log messages to keep. Supported values
                # are: FATAL, ERROR, WARN, INFO, DEBUG
                "severity": "INFO",

                # If DEBUG level is specified, this value is used. 0 is least verbose,
                # 99 is most verbose. Be cautious, Kea can generate lots and lots
                # of logs if told to do so.
                "debuglevel": 0
            }
        ]
    }
}

# Remove empty lists
dhcp4['Dhcp4'] = {k: v for k, v in dhcp4['Dhcp4'].items() if v is not None and v != []}

# check HA feature
if ha_config.get('mode', 'off') != 'off':
    client_name = ha_config.get('client_name', None)
    if client_name is None:
        client_name = node.name

    libdhcp_lease_cmds = {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so",
        "parameters": {}
    }

    libdhcp_ha = {
        "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_ha.so",
        "parameters": {
            "high-availability": [{
                "this-server-name": client_name,
                "mode": ha_config.get('mode'),
                "wait-backup-ack": False,
                "heartbeat-delay": ha_config.get('heartbeat-delay'),
                "max-response-delay": ha_config.get('max-response-delay'),
                "max-ack-delay": ha_config.get('max-ack-delay'),
                "max-unacked-clients": ha_config.get('max-unacked-clients'),
                "max-rejected-lease-updates": ha_config.get('max-rejected-lease-updates'),

                "peers": ha_config.get('peers'),
            }]
        }
    }

    if tls_enabled:
        for parameter in ['trust-anchor', 'cert-file', 'key-file']:
            libdhcp_ha['parameters']['high-availability'][0][parameter] = join('/etc/kea/ssl', dhcp_config.get('tls').
                                                                               get(parameter, None))

    dhcp4["Dhcp4"]['hooks-libraries'] = [libdhcp_lease_cmds, libdhcp_ha, ]





dhcp6 = {
    # DHCPv6 configuration starts here. This section will be read by DHCPv6 server
    # and will be ignored by other components.
    "Dhcp6": {
        # Add names of your network interfaces to listen on.
        "interfaces-config": {
            # You typically want to put specific interface names here, e.g. eth0
            # but you can also specify unicast addresses (e.g. eth0/2001:db8::1) if
            # you want your server to handle unicast traffic in addition to
            # multicast. (DHCPv6 is a multicast based protocol).
            "interfaces": []
        },

        # Kea supports control channel, which is a way to receive management commands
        # while the server is running. This is a Unix domain socket that receives
        # commands formatted in JSON, e.g. config-set (which sets new configuration),
        # config-reload (which tells Kea to reload its configuration from file),
        # statistic-get (to retrieve statistics) and many more. For detailed
        # description, see Sections 9.12, 16 and 15.
        "control-socket": {
            "socket-type": "unix",
            "socket-name": "/run/kea/kea6-ctrl-socket"
        },

        # Use Memfile lease database backend to store leases in a CSV file.
        # Depending on how Kea was compiled, it may also support SQL databases
        # (MySQL and/or PostgreSQL). Those database backends require more
        # parameters, like name, host and possibly user and password.
        # There are dedicated examples for each backend. See Section 8.2.2 "Lease
        # Storage" for details.
        "lease-database": {
            # Memfile is the simplest and easiest backend to use. It's an in-memory
            # C++ database that stores its state in CSV file.
            "type": "memfile",
            "lfc-interval": 3600
        },

        # Kea allows storing host reservations in a database. If your network is
        # small or you have few reservations, it's probably easier to keep them
        # in the configuration file. If your network is large, it's usually better
        # to use database for it. To enable it, uncomment the following:
        # "hosts-database": {
        #     "type": "mysql",
        #     "name": "kea",
        #     "user": "kea",
        #     "password": "kea",
        #     "host": "localhost",
        #     "port": 3306
        # },
        # See Section 8.2.3 "Hosts storage" for details.

        # Setup reclamation of the expired leases and leases affinity.
        # Expired leases will be reclaimed every 10 seconds. Every 25
        # seconds reclaimed leases, which have expired more than 3600
        # seconds ago, will be removed. The limits for leases reclamation
        # are 100 leases or 250 ms for a single cycle. A warning message
        # will be logged if there are still expired leases in the
        # database after 5 consecutive reclamation cycles.
        "expired-leases-processing": {
            "reclaim-timer-wait-time": 10,
            "flush-reclaimed-timer-wait-time": 25,
            "hold-reclaimed-time": 3600,
            "max-reclaim-leases": 100,
            "max-reclaim-time": 250,
            "unwarned-reclaim-cycles": 5
        },

        # These parameters govern global timers. Addresses will be assigned with
        # preferred and valid lifetimes being 3000 and 4000, respectively. Client
        # is told to start renewing after 1000 seconds. If the server does not
        # respond after 2000 seconds since the lease was granted, a client is
        # supposed to start REBIND procedure (emergency renewal that allows
        # switching to a different server).
        "renew-timer": 1000,
        "rebind-timer": 2000,
        "preferred-lifetime": 3000,
        "valid-lifetime": 4000,

        # These are global options. They are going to be sent when a client requests
        # them, unless overwritten with values in more specific scopes. The scope
        # hierarchy is:
        # - global
        # - subnet
        # - class
        # - host
        #
        # Not all of those options make sense. Please configure only those that
        # are actually useful in your network.
        #
        # For a complete list of options currently supported by Kea, see
        # Section 8.2.9 "Standard DHCPv6 Options". Kea also supports
        # vendor options (see Section 7.2.10) and allows users to define their
        # own custom options (see Section 7.2.9).
        "option-data": [
            # When specifying options, you typically need to specify
            # one of (name or code) and data. The full option specification
            # covers name, code, space, csv-format and data.
            # space defaults to "dhcp6" which is usually correct, unless you
            # use encapsulate options. csv-format defaults to "true", so
            # this is also correct, unless you want to specify the whole
            # option value as long hex string. For example, to specify
            # domain-name-servers you could do this:
            # {
            #     "name": "dns-servers",
            #     "code": 23,
            #     "csv-format": "true",
            #     "space": "dhcp6",
            #     "data": "2001:db8:2::45, 2001:db8:2::100"
            # }
            # but it's a lot of writing, so it's easier to do this instead:
            {
                "name": "dns-servers",
                "data": "2001:db8:2::45, 2001:db8:2::100"
            },

            # Typically people prefer to refer to options by their names, so they
            # don't need to remember the code names. However, some people like
            # to use numerical values. For example, DHCPv6 can optionally use
            # server unicast communication, if extra option is present. Option
            # "unicast" uses option code 12, so you can reference to it either
            # by "name": "unicast" or "code": 12. If you enable this option,
            # you really should also tell the server to listen on that address
            # (see interfaces-config/interfaces list above).
            {
                "code": 12,
                "data": "2001:db8::1"
            },

            # String options that have a comma in their values need to have
            # it escaped (i.e. each comma is preceded by two backslashes).
            # That's because commas are reserved for separating fields in
            # compound options. At the same time, we need to be conformant
            # with JSON spec, that does not allow "\,". Therefore the
            # slightly uncommon double backslashes notation is needed.

            # Legal JSON escapes are \ followed by "\/bfnrt character
            # or \u followed by 4 hexadecimal numbers (currently Kea
            # supports only \u0000 to \u00ff code points).
            # CSV processing translates '\\' into '\' and '\,' into ','
            # only so for instance '\x' is translated into '\x'. But
            # as it works on a JSON string value each of these '\'
            # characters must be doubled on JSON input.
            {
                "name": "new-posix-timezone",
                "data": "EST5EDT4\\\\,M3.2.0/02:00\\\\,M11.1.0/02:00"
            },

            # Options that take integer values can either be specified in
            # dec or hex format. Hex format could be either plain (e.g. abcd)
            # or prefixed with 0x (e.g. 0xabcd).
            {
                "name": "preference",
                "data": "0xf0"
            },

            # A few options are encoded in (length, string) tuples
            # which can be defined using only strings as the CSV
            # processing computes lengths.
            {
                "name": "bootfile-param",
                "data": "root=/dev/sda2, quiet, splash"
            }
        ],

        # Another thing possible here are hooks. Kea supports a powerful mechanism
        # that allows loading external libraries that can extract information and
        # even influence how the server processes packets. Those libraries include
        # additional forensic logging capabilities, ability to reserve hosts in
        # more flexible ways, and even add extra commands. For a list of available
        # hook libraries, see https:#gitlab.isc.org/isc-projects/kea/wikis/Hooks-available.
        # "hooks-libraries": [
        #   {
        #       # Forensic Logging library generates forensic type of audit trail
        #       # of all devices serviced by Kea, including their identifiers
        #       # (like MAC address), their location in the network, times
        #       # when they were active etc.
        #       "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_legal_log.so",
        #       "parameters": {
        #           "path": "/var/lib/kea",
        #           "base-name": "kea-forensic6"
        #       }
        #   },
        #   {
        #       # Flexible identifier (flex-id). Kea software provides a way to
        #       # handle host reservations that include addresses, prefixes,
        #       # options, client classes and other features. The reservation can
        #       # be based on hardware address, DUID, circuit-id or client-id in
        #       # DHCPv4 and using hardware address or DUID in DHCPv6. However,
        #       # there are sometimes scenario where the reservation is more
        #       # complex, e.g. uses other options that mentioned above, uses part
        #       # of specific options or perhaps even a combination of several
        #       # options and fields to uniquely identify a client. Those scenarios
        #       # are addressed by the Flexible Identifiers hook application.
        #       "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_flex_id.so",
        #       "parameters": {
        #           "identifier-expression": "relay6[0].option[37].hex"
        #       }
        #   }
        # ],

        # Below an example of a simple IPv6 subnet declaration. Uncomment to enable
        # it. This is a list, denoted with [ ], of structures, each denoted with
        # { }. Each structure describes a single subnet and may have several
        # parameters. One of those parameters is "pools" that is also a list of
        # structures.
        "subnet6": [
            # {
            #     # This defines the whole subnet. Kea will use this information to
            #     # determine where the clients are connected. This is the whole
            #     # subnet in your network. This is mandatory parameter for each
            #     # subnet.
            #     "subnet": "2001:db8:1::/64",
            #
            #     # Pools define the actual part of your subnet that is governed
            #     # by Kea. Technically this is optional parameter, but it's
            #     # almost always needed for DHCP to do its job. If you omit it,
            #     # clients won't be able to get addresses, unless there are
            #     # host reservations defined for them.
            #     "pools": [{"pool": "2001:db8:1::/80"}],
            #
            #     # Kea supports prefix delegation (PD). This mechanism delegates
            #     # whole prefixes, instead of single addresses. You need to specify
            #     # a prefix and then size of the delegated prefixes that it will
            #     # be split into. This example below tells Kea to use
            #     # 2001:db8:1::/56 prefix as pool and split it into /64 prefixes.
            #     # This will give you 256 (2^(64-56)) prefixes.
            #     "pd-pools": [
            #         {
            #             "prefix": "2001:db8:8::",
            #             "prefix-len": 56,
            #             "delegated-len": 64
            #
            #             # Kea also supports excluded prefixes. This advanced option
            #             # is explained in Section 9.2.9. Please make sure your
            #             # excluded prefix matches the pool it is defined in.
            #             # "excluded-prefix": "2001:db8:8:0:80::",
            #             # "excluded-prefix-len": 72
            #         }
            #     ],
            #     "option-data": [
            #         # You can specify additional options here that are subnet
            #         # specific. Also, you can override global options here.
            #         {
            #             "name": "dns-servers",
            #             "data": "2001:db8:2::dead:beef, 2001:db8:2::cafe:babe"
            #         }
            #     ],
            #
            #     # Host reservations can be defined for each subnet.
            #     #
            #     # Note that reservations are subnet-specific in Kea. This is
            #     # different than ISC DHCP. Keep that in mind when migrating
            #     # your configurations.
            #     "reservations": [
            #         # This is a simple host reservation. The host with DUID matching
            #         # the specified value will get an address of 2001:db8:1::100.
            #         {
            #             "duid": "01:02:03:04:05:0A:0B:0C:0D:0E",
            #             "ip-addresses": ["2001:db8:1::100"]
            #         },
            #
            #         # This is similar to the previous one, but this time the
            #         # reservation is done based on hardware/MAC address. The server
            #         # will do its best to extract the hardware/MAC address from
            #         # received packets (see 'mac-sources' directive for
            #         # details). This particular reservation also specifies two
            #         # extra options to be available for this client. If there are
            #         # options with the same code specified in a global, subnet or
            #         # class scope, the values defined at host level take
            #         # precedence.
            #         {
            #             "hw-address": "00:01:02:03:04:05",
            #             "ip-addresses": ["2001:db8:1::101"],
            #             "option-data": [
            #                 {
            #                     "name": "dns-servers",
            #                     "data": "3000:1::234"
            #                 },
            #                 {
            #                     "name": "nis-servers",
            #                     "data": "3000:1::234"
            #                 }],
            #
            #             # This client will be automatically added to certain
            #             # classes.
            #             "client-classes": ["special_snowflake", "office"]
            #         },
            #
            #         # This is a bit more advanced reservation. The client with the
            #         # specified DUID will get a reserved address, a reserved prefix
            #         # and a hostname.  This reservation is for an address that it
            #         # not within the dynamic pool.  Finally, this reservation
            #         # features vendor specific options for CableLabs, which happen
            #         # to use enterprise-id 4491. Those particular values will be
            #         # returned only to the client that has a DUID matching this
            #         # reservation.
            #         {
            #             "duid": "01:02:03:04:05:06:07:08:09:0A",
            #             "ip-addresses": ["2001:db8:1:0:cafe::1"],
            #             "prefixes": ["2001:db8:2:abcd::/64"],
            #             "hostname": "foo.example.com",
            #             "option-data": [
            #                 {
            #                     "name": "vendor-opts",
            #                     "data": "4491"
            #                 },
            #                 {
            #                     "name": "tftp-servers",
            #                     "space": "vendor-4491",
            #                     "data": "3000:1::234"
            #                 }
            #             ]
            #         },
            #
            #         # This reservation is using flexible identifier. Instead of
            #         # relying on specific field, sysadmin can define an expression
            #         # similar to what is used for client classification,
            #         # e.g. substring(relay[0].option[17],0,6). Then, based on the
            #         # value of that expression for incoming packet, the reservation
            #         # is matched.  Expression can be specified either as hex or
            #         # plain text using single quotes.
            #
            #         # Note: flexible identifier requires flex_id hook library to be
            #         # loaded to work.
            #         {
            #             "flex-id": "'somevalue'",
            #             "ip-addresses": ["2001:db8:1:0:cafe::2"]
            #         }
            #     ]
            # }
            # More subnets can be defined here.
            #      {
            #          "subnet": "2001:db8:2::/64",
            #          "pools": [ { "pool": "2001:db8:2::/80" } ]
            #      },
            #      {
            #          "subnet": "2001:db8:3::/64",
            #          "pools": [ { "pool": "2001:db8:3::/80" } ]
            #      },
            #      {
            #          "subnet": "2001:db8:4::/64",
            #          "pools": [ { "pool": "2001:db8:4::/80" } ]
            #      }
        ],

        # Client-classes can be defined here. See "client-classes" in Dhcp4 for
        # an example.

        # DDNS information (how the DHCPv6 component can reach a DDNS daemon)

        # Logging configuration starts here. Kea uses different loggers to log various
        # activities. For details (e.g. names of loggers), see Chapter 18.
        "loggers": [
            {
                # This specifies the logging for kea-dhcp6 logger, i.e. all logs
                # generated by Kea DHCPv6 server.
                "name": "kea-dhcp6",
                "output_options": [
                    {
                        # Specifies the output file. There are several special values
                        # supported:
                        # - stdout (prints on standard output)
                        # - stderr (prints on standard error)
                        # - syslog (logs to syslog)
                        # - syslog:name (logs to syslog using specified name)
                        # Any other value is considered a name of the file
                        "output": "stdout",

                        # Shorter log pattern suitable for use with systemd,
                        # avoids redundant information
                        "pattern": "%-5p %m\\n",

                        # This governs whether the log output is flushed to disk after
                        # every write.
                        # "flush": false,

                        # This specifies the maximum size of the file before it is
                        # rotated.
                        # "maxsize": 1048576,

                        # This specifies the maximum number of rotated files to keep.
                        # "maxver": 8
                    }
                ],
                # This specifies the severity of log messages to keep. Supported values
                # are: FATAL, ERROR, WARN, INFO, DEBUG
                "severity": "INFO",

                # If DEBUG level is specified, this value is used. 0 is least verbose,
                # 99 is most verbose. Be cautious, Kea can generate lots and lots
                # of logs if told to do so.
                "debuglevel": 0
            }
        ]
    }
}

dhcp_ddns = {
    # DHCP DDNS configuration starts here. This is a very simple configuration
    # that simply starts the DDNS daemon, but will not do anything useful.
    # See Section 11 for examples and details description.
    "DhcpDdns":
        {
            "ip-address": "127.0.0.1",
            "port": 53001,
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea-ddns-ctrl-socket"
            },
            "tsig-keys": [],
            "forward-ddns": {},
            "reverse-ddns": {},

            # Logging configuration starts here. Kea uses different loggers to log various
            # activities. For details (e.g. names of loggers), see Chapter 18.
            "loggers": [
                {
                    # This specifies the logging for D2 (DHCP-DDNS) daemon.
                    "name": "kea-dhcp-ddns",
                    "output_options": [
                        {
                            # Specifies the output file. There are several special values
                            # supported:
                            # - stdout (prints on standard output)
                            # - stderr (prints on standard error)
                            # - syslog (logs to syslog)
                            # - syslog:name (logs to syslog using specified name)
                            # Any other value is considered a name of the file
                            "output": "stdout",

                            # Shorter log pattern suitable for use with systemd,
                            # avoids redundant information
                            "pattern": "%-5p %m\\n"

                            # This governs whether the log output is flushed to disk after
                            # every write.
                            # "flush": false,

                            # This specifies the maximum size of the file before it is
                            # rotated.
                            # "maxsize": 1048576,

                            # This specifies the maximum number of rotated files to keep.
                            # "maxver": 8
                        }
                    ],
                    # This specifies the severity of log messages to keep. Supported values
                    # are: FATAL, ERROR, WARN, INFO, DEBUG
                    "severity": "INFO",

                    # If DEBUG level is specified, this value is used. 0 is least verbose,
                    # 99 is most verbose. Be cautious, Kea can generate lots and lots
                    # of logs if told to do so.
                    "debuglevel": 0
                }
            ]
        }
}

files = {
    # we moved to kea, so we need to delete old config files
    '/etc/dhcp/dhcpd.conf': {
        'delete': True,
    },
    '/etc/default/isc-dhcp-server': {
        'delete': True,
    },
    '/etc/dhcp/dhcpd.leases': {
        'delete': True,
    },


    '/etc/kea/kea-ctrl-agent.conf': {
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'content': format_config(ctrl_agent) + "\n",

        'needs': ['pkg_apt:kea'],
        'triggers': [
            'svc_systemd:kea-ctrl-agent.service:restart',
        ],
    },
    '/etc/kea/kea-dhcp4.conf': {
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'content': format_config(dhcp4) + "\n",

        'needs': ['pkg_apt:kea'],
        'triggers': [
            'svc_systemd:kea-dhcp4-server.service:restart',
        ],
    },
    '/etc/kea/kea-dhcp6.conf': {
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'content': format_config(dhcp6) + "\n",

        'needs': ['pkg_apt:kea'],
        'triggers': [
            'svc_systemd:kea-dhcp6-server.service:restart',
        ],
    },
    '/etc/kea/kea-dhcp-ddns.conf': {
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'content': format_config(dhcp_ddns) + "\n",

        'needs': ['pkg_apt:kea'],
        'triggers': [
            'svc_systemd:kea-dhcp-ddns-server.service:restart',
        ],
    },
}

directories = {
    '/etc/kea/ssl': {
        'owner': 'root',
        'group': 'root',
        'mode': '0755',
    }
}

# get Controll Agent TLS Certs
for parameter in ['trust-anchor', 'cert-file']:
    filename = dhcp_config.get('tls', {}).get(parameter, None)

    if filename is not None:
        files[join('/etc/kea/ssl', filename)] = {
            'content': get_file_contents(join(repo.path, "data", "certs", filename)),
            'content_type': 'text',
            'owner': "_kea",
            'group': "_kea",
            'mode': "0644",
            'needs': ['pkg_apt:kea'],
            'triggers': [
                'svc_systemd:kea-ctrl-agent.service:restart',
            ],
        }

for parameter in ['key-file']:
    filename = dhcp_config.get('tls', {}).get(parameter, None)

    if filename is not None:
        files[join('/etc/kea/ssl', filename)] = {
            'content': repo.vault.decrypt_file(join("certs", filename)),
            'content_type': 'text',
            'owner': "_kea",
            'group': "_kea",
            'mode': "0600",
            'needs': ['pkg_apt:kea'],
            'triggers': [
                'svc_systemd:kea-ctrl-agent.service:restart',
            ],
        }
