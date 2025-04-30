from core.functions import *

'''
# 恶意用户排查
  1. 排查 home 下用户
  2. 排查 /etc/passwd 下，拥有 shell 权限、root 权限、特殊权限的用户
  3. 排查 /etc/shadow 下，空口令用户（无密码登录用户）
  4. 排查 sudo 中权限异常用户
  5. 排查 拥有 authorized_keys 免密登录用户
'''


class UserAnalysis:
    def __init__(self, client):
        self.client = client
        self.user_list = []
        self.group_list = {}

        # 执行各模块检查
        self.check_home()
        self.check_history()
        self.check_ssh_keys()
        self.check_passwd()
        self.check_shadow()
        self.check_sudoers()

    @staticmethod
    def extract_users_from_output(output):
        return [line.strip().split()[-1] for line in output.splitlines() if line.strip()]

    def check_home(self):
        info = get_color('home 目录用户', 'green')
        result = exec_command(self.client, 'ls -al /home')
        if result['status'] and result['result']:
            self.user_list = [file['filename'] for file in list(get_file_list(result['result']).values())]
            get_output(info, '\n'.join(self.user_list))

    def check_history(self):
        info = get_color('home/.bash_history 排查', 'green')
        output = []

        # 检查 root 用户的 bash_history
        result = exec_command(self.client, f'cat /root/.bash_history')
        if result['status'] and result['result']:
            output.append(f'{"/root/.bash_history":<50}\t[!] {get_color("存在 bash_history")}')

        # 检查其他用户的 bash_history
        for user in self.user_list:
            result = exec_command(self.client, f'cat /home/{user}/.bash_history')
            if result['status'] and result['result']:
                output.append(f'{f"/home/{user}/.bash_history":<50}\t[!] {get_color("存在 bash_history")}')

        get_output(info, '\n'.join(output))

    def check_passwd(self):
        info = get_color('/etc/passwd 异常用户排查', 'green')
        result = exec_command(self.client, f'cat /etc/passwd')
        output = []

        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                parts = line.strip().split(':')
                if len(parts) >= 7:
                    user_name, user_uid, user_gid, _, _, _, user_shell = parts

                    issues = []
                    if ('nologin' not in user_shell) and (user_name != 'root'):
                        if "sh" in user_shell:
                            issues.append(get_color('拥有 shell 权限 [拥有系统 shell]', 'red'))
                        else:
                            issues.append(get_color('拥有 shell 权限 [请检测 shell]'))
                    if user_uid == '0' and user_name != 'root':
                        issues.append(get_color('root 标识用户', 'red'))
                    if user_gid == '0' and user_name != 'root':
                        issues.append(get_color('特权用户', 'red'))

                    if issues:
                        output.append(f'{"user: " + user_name:<20}\t{"shell: " + user_shell:<20}\t[!] {"、".join(issues)}')

        get_output(info, '\n'.join(output))

    def check_ssh_keys(self):
        info = get_color('SSH authorized_keys 排查', 'green')
        output = []

        # 检查 root 用户的 authorized_keys
        result = exec_command(self.client, f'cat /root/.ssh/authorized_keys')
        if result['status'] and result['result']:
            users = ', '.join(self.extract_users_from_output(result['result']))
            output.append(f'{"/root/.ssh/authorized_keys":<30}\t{"user list: " + get_color(users, "red"):<20}\t[!] {get_color("存在 SSH authorized_keys", "red")}')

        result = exec_command(self.client, f'find /root/.ssh/ -type f 2>/dev/null')
        if result['status'] and result['result']:
            tmp = f'{result["result"]:<30}\t'
            output.append(f'{tmp:<50}\t[!] {get_color("存在 SSH authorized_keys", "red")}')

        # 检查其他用户的 authorized_keys
        for user in self.user_list:
            result = exec_command(self.client, f'cat /home/{user}/.ssh/authorized_keys')
            if result['status'] and result['result']:
                users = ', '.join(self.extract_users_from_output(result['result']))
                output.append(f'{f"/home/{user}/.ssh/authorized_keys":<30}\t{"user list: " + get_color(users, "red"):<20}\t[!] {get_color("存在 SSH authorized_keys", "red")}')

        for user in self.user_list:
            result = exec_command(self.client, f'find /home/{user}/.ssh/ -type f 2>/dev/null')
            if result['status'] and result['result']:
                output.append(f'{result["result"]:<30}\t[!] {get_color("存在 SSH authorized_keys", "red")}')

        get_output(info, '\n'.join(output))

    def check_shadow(self):
        info = get_color('/etc/shadow 异常用户排查', 'green')
        result = exec_command(self.client, f'cat /etc/shadow')
        output = []

        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                parts = line.strip().split(':')
                user_name, hashcode = parts[0], parts[1]
                if not hashcode:
                    output.append(f'{"user: " + user_name:<50}\t[!] {get_color("空口令账户")}')

        get_output(info, '\n'.join(output))

    def check_sudoers(self):
        info = get_color('sudo 用户权限排查', 'green')
        result = exec_command(self.client, f'cat /etc/sudoers')
        output = []

        if result['status'] and result['result']:
            self.get_group()

            for line in result['result'].splitlines():
                line = line.strip()
                if ('ALL=(ALL)' in line or 'ALL=(root)' in line) and not line.startswith('#'):
                    parts = line.split()
                    user_or_group = parts[0]

                    if user_or_group.startswith('%'):  # 组
                        group_name = user_or_group[1:]
                        users_in_group = self.group_list.get(group_name, [])
                        tmp = f'{"group: " + group_name:<30}\t{"user: " + ", ".join(users_in_group):<20}'
                        output.append(f'{tmp:<50}\t[!] {get_color("sudo 权限组异常", "red")}')
                    else:
                        tmp = f'{"user: " + user_or_group:<50}'
                        output.append(f'{tmp:<50}\t[!] {get_color("sudo 权限组异常", "red")}')

        get_output(info, '\n'.join(output))

    def get_group(self):
        result = exec_command(self.client, f'cat /etc/group')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                parts = line.strip().split(':')
                # 组名:密码:占位符 GID:组内用户
                group_name, _, _, users = parts
                self.group_list[group_name] = [user.strip() for user in users.split(',') if user.strip()]
