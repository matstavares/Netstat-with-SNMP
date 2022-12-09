import argparse
import subprocess
import ipaddress


class SNMP:
    def __init__(
        self,
        ip,
        version,
        community,
        user,
        level,
        auth,
        passphrase,
        privacy,
        privacy_passphrase,
    ):
        self.ip = ip
        self.version = version
        self.community = community
        self.user = user
        self.level = level
        self.auth = auth
        self.passphrase = passphrase
        self.privacy = privacy
        self.privacy_passphrase = privacy_passphrase

    def getSNMPTable(
        self,
        bool_tcp,
        bool_udp,
        filter_Conn,
        filter_local_port,
        filter_remote_port,
    ):

        if filter_Conn == ["all"]:
            filter_Conn = ["listen", "established", "timeWait"]

        if filter_local_port == ["all"]:
            filter_local_port = []

        if filter_remote_port == ["all"]:
            filter_remote_port = []

        if (bool_tcp and bool_udp) or ((not bool_tcp) and (not bool_udp)):
            if self.version == str(3):
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        -u {self.user} \
                        -l {self.level} \
                        -a {self.auth} \
                        -A {self.passphrase} \
                        -x {self.privacy} \
                        -X {self.privacy_passphrase} \
                        RFC1213-MIB::tcpConnTable "
            else:
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        RFC1213-MIB::tcpConnTable "

            output = subprocess.getoutput(cmd)
            linhas = output.splitlines()
            matrix = []

            for i in linhas:
                matrix.append(i.split())

            saida = []
            saida2 = []
            colunas = []

            saida.append(linhas[0].split())
            if len(linhas) > 3:
                saida.append(linhas[2].split())

            saida2.append("-------------------------")
            saida2.append("")
            saida2.append(linhas[0])

            if len(linhas) > 3:
                saida2.append("")
                saida2.append(linhas[2])
                saida2.append(
                    "EstadoConexão      Endereço Local      Porta Local   Endereço Remoto   Porta Remota"
                )
            saida2.append("")

            for l in range(3, len(linhas)):
                escrevi = False

                for i in filter_Conn:
                    if i == "established":
                        if matrix[l][0] == "established":

                            if filter_local_port == [] and filter_remote_port == []:
                                for c in range(0, len(matrix[0])):
                                    colunas.append(matrix[l][c])
                                    escrevi = True
                            else:
                                if int(matrix[l][2]) in filter_local_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                                elif int(matrix[l][4]) in filter_remote_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                    elif i == "listen":
                        if matrix[l][0] == "listen":

                            if filter_local_port == [] and filter_remote_port == []:
                                for c in range(0, len(matrix[0])):
                                    colunas.append(matrix[l][c])
                                    escrevi = True
                            else:
                                if int(matrix[l][2]) in filter_local_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                                elif int(matrix[l][4]) in filter_remote_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                    elif i == "timeWait":
                        if matrix[l][0] == "timeWait":

                            if filter_local_port == [] and filter_remote_port == []:
                                for c in range(0, len(matrix[0])):
                                    colunas.append(matrix[l][c])
                                    escrevi = True
                            else:
                                if int(matrix[l][2]) in filter_local_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                                elif int(matrix[l][4]) in filter_remote_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                    if escrevi:
                        saida.append(colunas)
                        saida2.append(linhas[l])
                        break

            if self.version == str(3):
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        -u {self.user} \
                        -l {self.level} \
                        -a {self.auth} \
                        -A {self.passphrase} \
                        -x {self.privacy} \
                        -X {self.privacy_passphrase} \
                        RFC1213-MIB::udpTable "
            else:
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        RFC1213-MIB::udpTable "

            output = subprocess.getoutput(cmd)
            linhas = output.splitlines()

            saida2.append("")
            saida2.append("-------------------------")
            saida2.append("")

            saida2.append(linhas[0])

            if len(linhas) > 3:
                saida2.append("")
                saida2.append(linhas[2])
                saida2.append("  Endereço Local  Porta Local")

            saida2.append("")

            for l in range(3, len(linhas)):
                if filter_local_port == []:
                    saida.append(linhas[l].split())
                    saida2.append(linhas[l])
                else:
                    if int(linhas[l].split()[1]) in filter_local_port:
                        saida.append(linhas[l].split())
                        saida2.append(linhas[l])

            saida2.append("")
            saida2.append("-------------------------")

        elif bool_tcp:
            if self.version == str(3):
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        -u {self.user} \
                        -l {self.level} \
                        -a {self.auth} \
                        -A {self.passphrase} \
                        -x {self.privacy} \
                        -X {self.privacy_passphrase} \
                        RFC1213-MIB::tcpConnTable "
            else:
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        RFC1213-MIB::tcpConnTable "

            output = subprocess.getoutput(cmd)
            linhas = output.splitlines()

            matrix = []
            for i in linhas:
                matrix.append(i.split())

            saida = []
            saida2 = []
            colunas = []

            saida.append(linhas[0].split())
            if len(linhas) > 3:
                saida.append(linhas[2].split())

            saida2.append("-------------------------")
            saida2.append("")
            saida2.append(linhas[0])

            if len(linhas) > 3:
                saida2.append("")
                saida2.append(linhas[2])
                saida2.append(
                    "EstadoConexão      Endereço Local      Porta Local   Endereço Remoto   Porta Remota"
                )
            saida2.append("")

            for l in range(3, len(linhas)):
                escrevi = False

                for i in filter_Conn:
                    if i == "established":
                        if matrix[l][0] == "established":

                            if filter_local_port == [] and filter_remote_port == []:
                                for c in range(0, len(matrix[0])):
                                    colunas.append(matrix[l][c])
                                    escrevi = True
                            else:
                                if int(matrix[l][2]) in filter_local_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                                elif int(matrix[l][4]) in filter_remote_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True
                    elif i == "listen":
                        if matrix[l][0] == "listen":

                            if filter_local_port == [] and filter_remote_port == []:
                                for c in range(0, len(matrix[0])):
                                    colunas.append(matrix[l][c])
                                    escrevi = True
                            else:
                                if int(matrix[l][2]) in filter_local_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                                elif int(matrix[l][4]) in filter_remote_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                    elif i == "timeWait":
                        if matrix[l][0] == "timeWait":

                            if filter_local_port == [] and filter_remote_port == []:
                                for c in range(0, len(matrix[0])):
                                    colunas.append(matrix[l][c])
                                    escrevi = True
                            else:
                                if int(matrix[l][2]) in filter_local_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                                elif int(matrix[l][4]) in filter_remote_port:
                                    for c in range(0, len(matrix[0])):
                                        colunas.append(matrix[l][c])
                                        escrevi = True

                    if escrevi:
                        saida.append(colunas)
                        saida2.append(linhas[l])
                        break

            saida2.append("")
            saida2.append("-------------------------")
        else:
            if self.version == str(3):
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        -u {self.user} \
                        -l {self.level} \
                        -a {self.auth} \
                        -A {self.passphrase} \
                        -x {self.privacy} \
                        -X {self.privacy_passphrase} \
                        RFC1213-MIB::udpTable "
            else:
                cmd = f"snmptable {self.ip} \
                        -v {self.version} \
                        -c {self.community}  \
                        RFC1213-MIB::udpTable "

            output = subprocess.getoutput(cmd)
            linhas = output.splitlines()

            saida = []
            saida2 = []

            saida2.append("-------------------------")
            saida2.append("")
            saida2.append(linhas[0])
            if len(linhas) > 3:
                saida2.append("")
                saida2.append(linhas[2])
                saida2.append("  Endereço Local  Porta Local")
            saida2.append("")

            for l in range(3, len(linhas)):
                if filter_local_port == []:
                    saida.append(linhas[l].split())
                    saida2.append(linhas[l])
                else:
                    if int(linhas[l].split()[1]) in filter_local_port:
                        saida.append(linhas[l].split())
                        saida2.append(linhas[l])

            saida2.append("")
            saida2.append("-------------------------")
        return saida, saida2


if __name__ == "__main__":

    all_args = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    all_args.add_argument(
        "ip",
        type=str,
        nargs="?",
        default="127.0.0.1",
        help="Target ip address, if none, looking at localhost.",
    )

    all_args.add_argument(
        "-v",
        "--version",
        type=str,
        default="2c",
        required=False,
        help="Set the version of SNMP in use.",
    )

    all_args.add_argument(
        "-c",
        "--community",
        default="public",
        required=False,
        help="The community that the SNMP are communicating with.",
    )

    all_args.add_argument(
        "-TCP",
        "--TCP",
        default=False,
        required=False,
        action="store_true",
        help="Shows only TCP table.",
    )

    all_args.add_argument(
        "-UDP",
        "--UDP",
        default=False,
        required=False,
        action="store_true",
        help="Shows only UDP table.",
    )

    all_args.add_argument(
        "-R",
        "--Remote",
        type=int,
        default=["all"],
        nargs="*",
        required=False,
        help="Filter by remote ports used on TCP.",
    )

    all_args.add_argument(
        "-L",
        "--Local",
        type=int,
        default=["all"],
        nargs="*",
        required=False,
        help="Filter by local ports used on TCP and UDP.",
    )

    all_args.add_argument(
        "-s",
        "--state",
        type=str,
        default=["established"],
        nargs="*",
        required=False,
        help="Filter wich state should show: established, listen, timeWait.",
    )

    all_args.add_argument(
        "-u",
        "--user",
        type=str,
        required=False,
        help="User to login in SNMP v3.",
    )

    all_args.add_argument(
        "-l",
        "--level",
        type=str,
        # default="",
        required=False,
        help="Set the security level to SNMPv3.",
    )

    all_args.add_argument(
        "-a",
        "--auth",
        type=str,
        # default="MD5",
        required=False,
        help="Set the authentication protocol of SNMPv3 (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)",
    )

    all_args.add_argument(
        "-A",
        "--passphrase",
        type=str,
        # default="",
        required=False,
        help="Set the authentication protocol passphrase to SNMPv3.",
    )

    all_args.add_argument(
        "-x",
        "--privacy",
        type=str,
        # default="DES",
        required=False,
        help="Set the privacy protocol to SNMPv3 (DES|AES|AES-192|AES-256)",
    )

    all_args.add_argument(
        "-X",
        "--privacy_passphrase",
        type=str,
        # default="",
        required=False,
        help="Set the privacy protocol pass phrase to SNMPv3.",
    )

    args = all_args.parse_args()

    if args.version == str(3):
        if args.user is None:
            all_args.error("version 3 require -u to be defined, see --help.")
        if args.level is None:
            all_args.error("version 3 require -l to be defined, see --help.")
        if args.auth is None:
            all_args.error("version 3 require -a to be defined, see --help.")
        if args.passphrase is None:
            all_args.error("version 3 require -A to be defined, see --help.")
        if args.privacy is None:
            all_args.error("version 3 require -x to be defined, see --help.")
        if args.privacy_passphrase is None:
            all_args.error("version 3 require -X to be defined, see --help.")

    format_ip = ipaddress.ip_address(args.ip).__str__()

    snmp = SNMP(
        format_ip,
        args.version,
        args.community,
        args.user,
        args.level,
        args.auth,
        args.passphrase,
        args.privacy,
        args.privacy_passphrase,
    )

    print("")
    print(f"Asking to {format_ip}")
    print("")

    saida, saida2 = snmp.getSNMPTable(
        args.TCP, args.UDP, args.state, args.Local, args.Remote
    )

    for j in saida2:
        print(f"{j}")
