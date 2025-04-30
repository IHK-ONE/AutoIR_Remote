from datetime import datetime
import re
import os
import csv
import time as tm
import json
import urllib
import tarfile
import hashlib
import subprocess
import collections
from pathlib import Path
import requests

server = json.load(open('data/config.json'))['SafeLineWAF']['Server']
keywords = json.load(open('data/config.json', 'r'))['CheckKeywords']


def exec_command(client, command):
    # exec_command 命令执行，返回结果，数据类型
    # {
    #     'status': False, -> bool
    #     'result': stderr_output -> str
    # }

    stdin, stdout, stderr = client.exec_command(command)
    stdout_output = stdout.read().decode().strip()
    stderr_output = stderr.read().decode().strip()

    result = {'status': False, 'result': stderr_output}
    if stdout_output:
        result.update({'status': True, 'result': stdout_output})

    return result


def sftp_download(client, origin_path, download_path):
    # SFTP 传输函数
    sftp = client.open_sftp()
    sftp.get(origin_path, download_path)
    return


def sftp_upload(client, local_path, server_path):
    # SFTP 传输函数
    sftp = client.open_sftp()
    sftp.put(local_path, server_path)
    return


def get_file_list(files):
    # 将 ls -al 的数据转换为列表
    file_list = {}
    files = files.splitlines()[1:]
    for i in range(len(files)):
        file = files[i].strip()
        parts = re.split(r'\s+', file.strip())
        perm = parts[0].strip('.').strip('+')  # 文件权限
        link = parts[1]  # 硬链接数
        owner = parts[2]  # 文件拥有者
        group = parts[3]  # 所在用户组
        size = parts[4]  # 文件大小
        time = get_time(parts[5:8])  # 文件时间
        filename = ' '.join(_ for _ in parts[8:])  # 文件名
        if filename not in ['.', '..']:
            file_list[i] = {'perm': perm, 'link': link, 'owner': owner, 'group': group, 'size': size, 'time': time, 'filename': filename}
    return file_list


def get_color(string, color='yellow'):
    # print("\033[显示方式;前景颜色;背景颜色m strings \033[0m")

    if color == 'red':
        return f'\033[0;31m{string}\033[0m'
    elif color == 'green':
        return f'\033[0;32m{string}\033[0m'
    elif color == 'yellow':
        return f'\033[0;33m{string}\033[0m'


def check_keyword_filter(content):
    # 对关键字进行标红
    for token in keywords:
        if token in content:
            content = content.replace(token, get_color(token, 'red'))
    return content


def get_output(info, output):
    # 格式化输出最终，同时该方法保留，不在类函数直接 print 便于后续修改为 return 并接入第三方平台（web端开发中）

    if len(output):
        formatted_info = f'[success] {info} :\n'
        formatted_output = ''

        for line in output.splitlines():
            line = check_keyword_filter(line.strip())
            formatted_output += f'\t{line}\n'

        print(formatted_info + formatted_output)  # 格式化输出模式

    else:
        print(f'{"[success] " + info:<60}\t[-] {get_color("safe 无风险", "green")}\n')


def get_time(time):
    # 时间转换，用于本地时间戳的判断

    month_map = {
        'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
        'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
        'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
    }

    mouth = month_map[time[0]]
    day = time[1]

    if ":" in time[2]:
        return f"{datetime.now().year}年{mouth}月{day}日 {time[2]}"
    return f"{time[2]}年{mouth}月{day}日"


def get_time_path():
    # 返回 %Y_%m_%d_%H_%M_%S 时间戳
    return datetime.now().strftime("%Y_%m_%d_%H_%M_%S")


def check_safe_local(content):
    # 检测恶意 shell
    # Author：咚咚呛
    # Github：https://github.com/grayddq/GScan

    try:
        if (('bash' in content) and (('/dev/tcp/' in content) or ('telnet ' in content) or ('nc ' in content) or (('exec ' in content) and ('socket' in content)) or ('curl ' in content) or ('wget ' in content) or ('lynx ' in content) or ('bash -i' in content))) or (".decode('base64')" in content) or ("exec(base64.b64decode" in content):
            return content
        elif ('/dev/tcp/' in content) and (('exec ' in content) or ('ksh -c' in content)):
            return content
        elif ('exec ' in content) and (('socket.' in content) or (".decode('base64')" in content)):
            return content

        elif (('wget ' in content) or ('curl ' in content)) and ((' -O ' in content) or (' -s ' in content)) and (' http' in content) and (('php ' in content) or ('perl' in content) or ('python ' in content) or ('sh ' in content) or ('bash ' in content)):
            return content
        return ''
    except:
        return ''


def check_safe_safeline(content):
    try:
        response = requests.get(server + content)
        if response.status_code == 403:
            return content
        return ''
    except:
        return ''
