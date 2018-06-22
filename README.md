bw.bundle.dhcp
--------------
Bundlewrap Bundle for isc dhcp

default Metadata
----------------

```python
'dhcp': {
    'authoritative': True,
    'bootp': True,
    'log': 'local7',

    'lease-time': 7200,
    'max-lease-time': 43200,

    'vendor_options': {
        'snom': {
            'tftp-server-name': {
                'code': 66,
                'type': 'text',
            },
            'bootfile-name': {
                'code': 67,
                'type': 'text',

            },
        },
    },

    'classes': {
        'snom': {
            'match': 'if substring (option vendor-class-identifier, 0, 4) = "snom"',
            'vendors': ['snom', ],
            'options': {
                'tftp-server-name': '"tftp://192.168.0.1"',
                'snom.tftp-server-name': '"tftp://192.168.0.1"',
                'ntp-servers': '192.168.0.1',
                'bootfile-name': '= concat("snom/",option vendor-class-identifier,".htm")',
                'snom.bootfile-name': '= concat("snom/",option vendor-class-identifier,".htm")',
            },
            'add_raw_parameter': [
                'next-server 192.168.0.1;',
                'filename "snom/snom370.cfg";',
            ]
        },
    },

    'subnets': {
        '192.168.0.0/24': {
            'range': ['192.168.0.100', '192.168.0.190'],
            'options': {
                'routers': '192.168.0.1',
                'broadcast-address': '192.168.0.255',
                'domain-name': '"home"',
                'domain-name-servers': '192.168.0.1',
            },
            'on': {
                'commit': [
                    'set ClientIP = binary-to-ascii(10, 8, ".", leased-address);',
                    'set ClientMac = binary-to-ascii(16, 8, ":", substring(hardware, 1, 6));',
                    'set ClientName = pick-first-value ( option fqdn.hostname, option host-name );',

                    'log("=============[ START COMMIT ]================");',
                    'log("The host name is:");',
                    'log(ClientName);',

                    'log(concat("Commit: IP: " , ClientIP, " Mac: ", ClientMac, " Hostname: " , ClientName));',
                    'execute("/etc/dhcp/dhcp-event","commit", ClientIP, ClientMac, ClientName, "auth");',
                    'log("============[ END COMMIT ]==================");',
                ],
                'release': [
                    'set ClientIP = binary-to-ascii(10, 8, ".", leased-address);',
                    'set ClientMac = binary-to-ascii(16, 8, ":", substring(hradware, 1, 6));',
                    'set ClientName = pick-first-value ( option fqdn.hostname, option host-name );',

                    'log("============[ START RELEASE ]===============");',
                    'log(concat("Release: IP: ", ClientIP, " Mac: ", ClientMac, " Hostname: ", ClientName));',
                    'execute("/etc/dhcp/dhcp-event", "release", ClientIP, ClientMac, ClientName, "auth");',
                    'log("===========[ END RELEASE ]==================");',
                ],
                'expiry': [
                    'set ClientIP = binary-to-ascii(10, 8, ".", leased-address);',
                    'set ClientMac = binary-to-ascii(16, 8, ":" , substring(hardware, 1, 6));',
                    'set ClientName = pick-first-value ( option fqdn.hostname, option host-name );',

                    'log("===========[ START EXPIRY ]================");',
                    'log(concat("Expiry: IP: ", ClientIP, " Mac: ", ClientMac, " Hostname: ", ClientName));',
                    'execute("/etc/dhcp/dhcp-event", "expiry", ClientIP, ClientMac, ClientName, "auth");',
                    'log("===========[ END EXPIRY ] =================");',
                ],
            }
        },
    },

    'hosts': {
        # rechner
        'host1': {
            'mac': '00:23:32:xx:xx:xx',
            'ip': '192.168.0.2',
            'options': {
                'host-name': '"host1"',
            }
        },
        'host2': {
            'mac': '00:01:02:xx:xx:xx',
            'ip': '192.168.0.3',
        },
    },
},
```

The Hosts are extendet by all hosts managed in Bundlewrap which have networks, which are defined (192.168.0.0/24 in this example).
There will be an exception, if a mac or ip is used twice.