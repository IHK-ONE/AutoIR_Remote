import paramiko
import argparse
from core.core import *


def parse_args():
    parser = argparse.ArgumentParser(description="AutoIR 自动化应急响应")
    parser.add_argument('-t', dest='ip', required=True, help='Target IP address 目标地址')
    parser.add_argument('-p', dest='port', type=int, default=22, help='SSH port 默认 22 端口')
    parser.add_argument('-u', dest='username', default='root', help='SSH username 默认 root')
    parser.add_argument('-k', dest='password', default='root', help='SSH password 默认 root')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(args.ip, args.port, args.username, args.password)

    main(client)
