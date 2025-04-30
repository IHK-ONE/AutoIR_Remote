from core.functions import *

'''
# HijackAnalysis 劫持排查
  环境变量劫持
'''


def command_format(check, command):
    return 'env -i /usr/bin/' + command if check else command


class HijackAnalysis:
    def __init__(self, client):
        self.client = client
        self.hijack = False
        self.hijack_list = []
        self.output = []

        self.check_hijack()

    def check_export(self, filename, data):
        # 匹配环境变量
        try:
            export_list = re.findall(r'export (.*)=(.*)', data)
            for key, value in export_list:
                if key in ('PATH', 'LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH', 'PROMPT_COMMAND') and value != '"$PATH:${snap_bin_path}"':
                    self.hijack_list.append(key)
                    status = f'[+] {get_color(key + " 环境变量劫持", "red")}'
                else:
                    status = f'[!] {get_color("环境变量劫持")}'
                self.output.append(f'{"filename: " + filename:<50}\t{"export" + key + "=" + value:<70}\t{status:<30}')
        except:
            pass

    def process_files(self, file_list, base_path=''):
        for file in file_list:
            path = f'{base_path}{file}' if base_path else file
            command = command_format(self.hijack, f'cat {path}')
            result = exec_command(self.client, command)

            if result['status'] and result['result']:
                self.check_export(path, result['result'])

    def check_hijack(self):
        info = get_color("环境变量劫持排查：", "green") + '\n需要手动排查，部分恶意脚本可能会通过调用环境变量进行绕过'

        # 常规目录环境变量排查
        common_files = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc', '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
        home_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

        # 检查是否被劫持
        result = exec_command(self.client, 'ls -al .')
        if result['status'] and result['result'][:5] != 'total':
            result = exec_command(self.client, 'env -i /usr/bin/ls -al .')
            if result['status'] and result['result'][:5] == 'total':
                self.hijack = True

        # 处理常规文件
        self.process_files(common_files)

        # 处理 /etc/profile.d/ 目录下的文件
        profile_d_files = []
        profile_d_command = command_format(self.hijack, 'ls -al /etc/profile.d/')
        profile_d_result = exec_command(self.client, profile_d_command)
        if profile_d_result['status'] and profile_d_result['result']:
            profile_d_files = [file['filename'] for file in get_file_list(profile_d_result['result']).values()]
        self.process_files(profile_d_files, '/etc/profile.d/')

        # 处理 HOME 目录下的用户文件
        user_list = []
        home_dir_command = command_format(self.hijack, 'ls -al /home')
        home_dir_result = exec_command(self.client, home_dir_command)
        if home_dir_result['status'] and home_dir_result['result']:
            user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]

        self.process_files([f'/home/{user}/{f}' for user in user_list for f in home_files])

        get_output(info, '\n'.join(self.output))
        if self.hijack_list and input(get_color('检测到当前环境变量已被劫持，是否继续？继续可能会有报错和卡住产生 [enter/n]', 'red')) == "n":
            exit(0)
