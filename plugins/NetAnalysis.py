from core.functions import *

class NetAnalysis:
    def __init__(self, client):
        self.client = client
        self.ip_list = ["127.0.0.1", "localhost", "0.0.0.0"]

        self.get_localhost()
        self.check_network()
        self.check_eth()
        self.check_hosts()

    def get_localhost(self):
        result = exec_command(self.client, 'ip -4 addr show')

        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                line = line.strip()
                if "inet" in line:
                    try:
                        ip = re.split(r'\s+', line)[1].split('/')[0]
                        self.ip_list.append(ip)
                    except:
                        pass

    def check_network(self):
        info = f'{get_color("ss 排查", "green")}\n有些恶意外联使用同一网段本地测试，故保留同一网段的外连链接'
        output = []

        result = exec_command(self.client, 'ss -anutp')
        if result.get('status') and result.get('result'):
            for line in result['result'].splitlines()[1:]:
                try:
                    parts = re.split(r'\s+', line.strip())
                    local, remote, pid_program = parts[4], parts[5], parts[-1]
                    local_addr, local_port = local.split(':')
                    remote_addr, remote_port = remote.rsplit(':')

                    if remote_addr not in self.ip_list and remote_port != "*":
                        output.append(
                            f'local :{local:<20}\tremote :{remote:<20}\tpid :{pid_program:<40}\t[!] {get_color("发现远程连接", "red")}')
                    elif local_port and local_port != "*":
                        output.append(f'local :{local:<20}\tremote :{remote:<20}\tpid :{pid_program:<40}\t[!] {get_color("发现开启端口")}')

                except:
                    pass

            get_output(info, "\n".join(output))

    def check_eth(self):
        info = f'{get_color("网卡排查", "green")}\n建议进行 tcpdump -i any 或者使用 tcpdump -i 网卡 -w output.pcap 捕获流量'
        result = exec_command(self.client, 'ls /sys/class/net')

        if result.get('status'):
            output = [f'网卡: {line.strip():<50}\t[!] {get_color("网卡检测")}' for line in result['result'].splitlines()]
            get_output(info, "\n".join(output))

    def check_hosts(self):
        info = get_color('hosts 排查', 'green') + '\n仅排除非本地 ipv4 的 hosts'
        output = ''

        result = exec_command(self.client, f'cat /etc/hosts')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                line = line.strip()
                try:
                    parts = re.split(r'\s+', line.strip())
                    if parts and not parts[0].startswith('#'):
                        ip, *domains = parts
                        if ip and ip not in self.ip_list:
                            self.ip_list.append(ip)
                            output += f'ip: {ip:<15}\tdomain: {"、".join(domains):<40}\t[!] {get_color("恶意 ip 解析域名")}\n'
                except:
                    pass

            get_output(info, output)
