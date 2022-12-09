# Netstat-with-SNMP
Looking on TCP and UDP connections

# Help
```
usage: netstat.py [-h] [-v VERSION] [-c COMMUNITY] [-TCP] [-UDP]
                  [-R [REMOTE ...]] [-L [LOCAL ...]] [-s [STATE ...]]
                  [-u USER] [-l LEVEL] [-a AUTH] [-A PASSPHRASE] [-x PRIVACY]
                  [-X PRIVACY_PASSPHRASE]
                  [ip]

positional arguments:
  ip                    Target ip address, if none, looking at localhost.
                        (default: 127.0.0.1)
options:
  -h, --help            show this help message and exit
  -v VERSION, --version VERSION
                        Set the version of SNMP in use. (default: 2c)
  -c COMMUNITY, --community COMMUNITY
                        The community that the SNMP are communicating with.
                        (default: public)

  -TCP, --TCP           Shows only TCP table. (default: False)

  -UDP, --UDP           Shows only UDP table. (default: False)

  -R [REMOTE ...], --Remote [REMOTE ...]
                        Filter by remote ports used on TCP. (default: ['all'])

  -L [LOCAL ...], --Local [LOCAL ...]
                        Filter by local ports used on TCP and UDP. (default:
                        ['all'])

  -s [STATE ...], --state [STATE ...]
                        Filter wich state should show: established, listen or
                        timeWait. (default: ['established'])

  -u USER, --user USER  User to login in SNMP v3. (default: None)

  -l LEVEL, --level LEVEL
                        Set the security level to SNMPv3. (default: None)

  -a AUTH, --auth AUTH  Set the authentication protocol of SNMPv3
                        (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512) (default:
                        None)

  -A PASSPHRASE, --passphrase PASSPHRASE
                        Set the authentication protocol passphrase to SNMPv3.
                        (default: None)

  -x PRIVACY, --privacy PRIVACY
                        Set the privacy protocol to SNMPv3
                        (DES|AES|AES-192|AES-256) (default: None)

  -X PRIVACY_PASSPHRASE, --privacy_passphrase PRIVACY_PASSPHRASE
                        Set the privacy protocol pass phrase to SNMPv3.
                        (default: None)
