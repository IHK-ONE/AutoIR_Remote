from core.functions import *

class BackdoorAnalysis:
    def __init__(self, client):
        self.client = client
        self.safeline_server = check_safe_safeline('bash -i')
        if not self.safeline_server:
            input('[-] ' +  get_color('后门排查警告：雷池 WAF 服务并未开启，键入 [enter] 继续'))

        self.check_ld_so_preload()
        self.check_cron()
        self.check_ssh()
        self.check_ssh_wrapper()
        self.check_inetd()
        self.check_xinetd()
        self.check_profile()
        self.check_rc()
        self.check_startup()
        self.check_setuid()

    def get_files(self, directory):
        file_list = []
        result = exec_command(self.client, f'ls -al {directory}')
        if result and result.get('status') and result.get('result'):
            for file in get_file_list(result['result']).values():
                filename = file['filename']
                if '->' in filename:
                    filename = filename.split(' -> ')[0]
                file_list.append(filename)
        return file_list

    def check_malicious_content(self, file_path):
        # 恶意命令检测
        output = ''
        result = exec_command(self.client, f'cat {file_path}')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                if not line.startswith('#'):
                    malicious_a = check_safe_local(line.strip())
                    malicious_b = ''
                    if self.safeline_server:
                        malicious_b = check_safe_safeline(line.strip())
                    if malicious_a or malicious_b:
                        output += f'file: {file_path:<40}\tcontent: {malicious_a + malicious_b:<40}\t[!] {get_color("恶意命令执行")}\n'
        return output

    def check_ld_so_preload(self):
        info = get_color('/etc/ld.so.preload 后门排查', 'green')
        output = ''

        result = exec_command(self.client, f'cat /etc/ld.so.preload')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    output += f'{line:<50}\t[!] {get_color("ld.so.preload 后门！", "red")}\n'

        get_output(info, output)

    def check_cron(self):
        info = get_color('计划任务后门排查', 'green') + '\n排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段'
        output = ''

        cron_dirs = ['/var/spool/cron', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.hourly', '/etc/cron.monthly']

        for cron_dir in cron_dirs:
            for file in self.get_files(cron_dir):
                output += self.check_malicious_content(f'{cron_dir}/{file}')

        get_output(info, output)

    def check_ssh(self):
        info = get_color('/usr/sbin/sshd 软连接后门排查', 'green')
        output = ''

        result = exec_command(self.client, 'ls -al /usr/sbin/sshd')
        if result['status'] and result['result'] and '>' in result['result']:
            output += f'content: {result["result"]:<50}\t[!] {get_color("sshd 已被劫持", "red")}\n'

        get_output(info, output)

    def check_ssh_wrapper(self):
        info = get_color('/usr/sbin/sshd ssh wrapper 后门排查', 'green') + '\n排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段'
        output = ''

        result = exec_command(self.client, 'strings /usr/sbin/sshd')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                malicious_a = check_safe_local(line.strip())
                malicious_b = ''
                if self.safeline_server:
                    malicious_b = check_safe_safeline(line.strip())
                if malicious_a or malicious_b:
                    if '\033' in malicious_a + malicious_b:
                        output += f'file: {"/usr/sbin/sshd":<40}\tcontent: {malicious_a + malicious_b}\t {get_color("恶意 shell 命令", "red")}\n'
                    else:
                        output += f'file: {"/usr/sbin/sshd":<40}\tcontent: {malicious_a + malicious_b}\t[!] {get_color("ssh wrapper 劫持")}\n'

        get_output(info, output)

    def check_inetd(self):
        info = get_color('/etc/inetd.conf 后门排查', 'green')
        output = self.check_malicious_content('/etc/inetd.conf')
        get_output(info, output)

    def check_xinetd(self):
        info = get_color('xinetd 后门排查', 'green')
        output = ''

        for file in self.get_files('/etc/xinetd.conf/'):
            output += self.check_malicious_content(f'/etc/xinetd.conf/{file}')

        get_output(info, output)

    def check_setuid(self):
        info = get_color('SUID 后门排查', 'green')
        output = ''

        result = exec_command(self.client, "find / ! -path '/proc/*' -type f -perm -4000 2>/dev/null")
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                output += f'command {line.strip():<50}\t[!] {get_color("SUID 后门", "red")}\n'

        get_output(info, output)

    def check_startup(self):
        info = get_color('启动项排查', 'green') + '\n排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段'
        output = ''

        init_paths = ['/etc/init.d', '/etc/rc.d', '/etc/systemd/system', '/usr/local/etc/rc.d']
        init_files = ['/etc/rc.local', '/usr/local/etc/rc.local', '/etc/conf.d/local.start', '/etc/inittab']

        for path in init_paths:
            for file in self.get_files(path):
                output += self.check_malicious_content(f'{path}/{file}')

        for file in init_files:
            output += self.check_malicious_content(f'{file}')

        get_output(info, output)

    def check_profile(self):
        info = get_color('/etc/profile.d 后门排查', 'green') + '\n排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段'
        output = ''

        for file in self.get_files('/etc/profile.d'):
            output += self.check_malicious_content(f'/etc/profile.d/{file}')

        get_output(info, output)


    def check_rc(self):
        info = get_color('bashrc 等初始化排查', 'green') + '\n排查基于雷池 WAF 拦截，可能并不准确，建议重点关注包含 bash 片段'
        output = ''

        init_paths = ['/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/etc/bashrc', '/etc/profile', '/etc/csh.login', '/etc/csh.cshrc']
        init_files = ['.bashrc', '.bash_profile', '.tcshrc', '.cshrc']

        for path in init_paths:
            output += self.check_malicious_content(path)

        user_list = []
        home_dir_result = exec_command(self.client, 'ls -al /home')
        if home_dir_result['status'] and home_dir_result['result']:
            user_list = [file['filename'] for file in get_file_list(home_dir_result['result']).values()]

        for user in user_list:
            for file in init_files:
                output += self.check_malicious_content(f'/home/{user}/{file}')

        get_output(info, output)