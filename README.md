# Netstat-with-SNMP
Looking on TCP and UDP connections

# Help
```
usage: netstat.py [-h] [-TCP] [-UDP] [-R [REMOTE ...]] [-L [LOCAL ...]] [-c COMMUNITY] [-v VERSION] [-s [STATE ...]] [ip]

positional arguments:
  ip                    Target ip address, if none, looking at localhost.

options:
  -h, --help            show this help message and exit
  -TCP, --TCP           Shows only TCP table.
  -UDP, --UDP           Shows only UDP table.
  -R [REMOTE ...], --Remote [REMOTE ...]
                        Filter by remote ports, used on TCP.
  -L [LOCAL ...], --Local [LOCAL ...]
                        Filter by local ports, used on TCP and UDP.
  -c COMMUNITY, --community COMMUNITY
                        The community that the SNMP are communicating with.
  -v VERSION, --version VERSION
                        Set the version of SNMP in use.
  -s [STATE ...], --state [STATE ...]
                        Filter wich state should show: established, listen, timeWait.
