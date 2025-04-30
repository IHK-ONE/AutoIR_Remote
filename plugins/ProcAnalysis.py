from core.functions import *

'''
# 恶意进程排查
  1.排查 恶意挖矿脚本
  2.排查 恶意启动，恶意命令执行的进程
  3.排查 隐藏pid
  4.排查 被恶意替换命令名称的进程
  5.排查 被恶意 mount 挂载的进程
'''

check_proc = json.load(open('data/info_proc.json'))
privilege_escalation = ['aa-exec', 'ansible-playbook', 'ansible-test', 'aoss', 'apt-get', 'apt', 'ash', 'at', 'awk', 'aws', 'bash', 'batcat', 'bconsole', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug', 'c89', 'c99', 'cabal', 'capsh', 'cdist', 'certbot', 'check_by_ssh', 'choom', 'cobc', 'composer', 'cowsay', 'cowthink', 'cpan', 'cpio', 'cpulimit', 'crash', 'csh', 'csvtool', 'dash', 'dc', 'debugfs', 'distcc', 'dmesg', 'docker', 'dotnet', 'dpkg', 'dstat', 'dvips', 'easy_install', 'eb', 'ed', 'elvish', 'emacs', 'enscript', 'env', 'ex', 'expect', 'facter', 'find', 'fish', 'flock', 'ftp', 'gawk', 'gcc', 'gcloud', 'gdb', 'gem', 'genie', 'ghc', 'ghci', 'gimp', 'ginsh', 'git', 'grc', 'gtester', 'hping3', 'iftop', 'ionice', 'irb', 'ispell', 'jjs', 'joe', 'journalctl', 'jrunscript', 'jtag', 'julia', 'knife', 'ksh', 'latex', 'latexmk', 'ld.so', 'less', 'lftp', 'loginctl', 'logsave', 'ltrace', 'lua', 'lualatex', 'luatex', 'mail', 'make', 'man', 'mawk', 'minicom', 'more', 'msfconsole', 'msgfilter', 'multitime', 'mysql', 'nano', 'nawk', 'ncdu', 'ncftp', 'neofetch', 'nice', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter', 'octave', 'openvpn', 'pandoc', 'pdb', 'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec', 'pg', 'php', 'pic', 'pico', 'pip', 'posh', 'pry', 'psftp', 'psql', 'puppet', 'pwsh', 'python', 'rake', 'rc', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'rtorrent', 'ruby', 'run-mailcap', 'run-parts', 'runscript', 'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen', 'script', 'scrot', 'sed', 'service', 'setarch', 'setlock', 'sftp', 'sg', 'slsh', 'smbclient', 'socat', 'softlimit', 'split', 'sqlite3', 'sqlmap', 'ssh-agent', 'ssh', 'sshpass', 'start-stop-daemon', 'stdbuf', 'strace', 'tar', 'task', 'taskset', 'tasksh', 'tclsh', 'tdbtool', 'telnet', 'tex', 'time', 'timedatectl', 'timeout', 'tmate', 'tmux', 'top', 'torify', 'torsocks', 'tshark', 'unshare', 'vagrant', 'valgrind', 'vi', 'view', 'vim', 'vimdiff', 'volatility', 'watch', 'wget', 'wish', 'xargs', 'xdg-user-dir', 'xdotool', 'xelatex', 'xetex', 'yarn', 'yash', 'zathura', 'zip', 'zsh', 'zypper']


class ProcAnalysis:
    def __init__(self, client):
        self.client = client
        self.ps = {}

        self.safeline_server = check_safe_safeline('bash -i')
        if not self.safeline_server:
            input('[-] ' + get_color('进程排查警告：雷池 WAF 服务并未开启，键入 [enter] 继续'))
        self.get_ps()
        self.check_mine()
        self.check_exec()
        self.check_pid()
        self.check_exe()
        self.check_mount()

    def get_ps(self):
        result = exec_command(self.client, 'ps -aux')

        if result['status'] and result['result']:
            for line in result['result'].splitlines()[1:]:
                try:
                    parts = re.split(r'\s+', line.strip())
                    pid = int(parts[1])
                    command = ' '.join(parts[10:])

                    exe = command.split()[0]
                    if ':' in exe:
                        exe = exe.split(':')[0]
                    elif '/' in exe:
                        exe = Path(exe).name
                    elif '(' in exe:
                        exe = exe[1:-1]

                    self.ps[pid] = {
                        'user': parts[0],
                        'cpu': float(parts[2]),
                        'mem': float(parts[3]),
                        'tty': parts[6],
                        'time': parts[9],
                        'command': ' '.join(parts[10:]),
                        'exe': exe
                    }
                except:
                    pass

    def check_mine(self):
        info = get_color('挖矿脚本排查', 'green')
        output = ''
        for pid, proc in self.ps.items():
            cpu, mem, command = proc['cpu'], proc['mem'], proc['command']
            if cpu > 50.0 or mem > 50.0:
                output += f'PID: {pid:<8}\tCPU: {cpu:<5}\tMEM: {mem:<5}\tCOMMAND: {command:<40}\t[!] {get_color("疑似挖矿脚本，cpu/mem 占用超过 50%", "red")}\n'
        get_output(info, output)

    def check_exec(self):
        info = get_color('恶意执行排查', 'green')
        output = ''
        root_command = []

        for pid, proc in self.ps.items():
            user, tty, command, exe = proc['user'], proc['tty'], proc['command'], proc['exe']
            reasons = []

            if 'ttyS' not in tty and tty != '?':
                reasons.append('tty 虚拟终端执行命令')
            if './' in command:
                reasons.append('通过相对路径运行命令')
            if user == 'root' and exe not in root_command:
                root_command.append(exe)
            if check_safe_local(command) or (self.safeline_server and check_safe_safeline(command)):
                reasons.append('疑似命令执行')
            if reasons:
                output += f'PID: {pid:<8}\tTTY: {tty:<8}\tCOMMAND: {command:<60}\t[!] {get_color(", ".join(reasons), "red")}\n'

        get_output(info, output)

        info = get_color('root 权限用户命令排查', 'green')
        output = ''

        for command in root_command:
            if command.startswith('[') or command.endswith(']'):
                continue
            for check in privilege_escalation:
                if check in command:
                    output += f'{"command: " + command:<50}\t[!]{get_color("疑似可 root 提权", "red")}\n'
                    break
        get_output(info, output)

    def check_pid(self):
        info = get_color('PID 隐藏排查', 'green')
        output = ''

        result_pid = exec_command(self.client, 'ls /proc')
        result_self = exec_command(self.client, 'ls -al /proc/self')

        if result_pid['status'] and result_self['status']:
            try:
                current_pid = re.findall(r'(\d+)', result_pid['result'])  # 确定所有 pid
                self_pid = re.search(r'-> (\d+)', result_self['result']).group(1)  # 匹配 self 的 pid

                for pid in current_pid:
                    if int(pid) not in self.ps and (int(pid) not in range(int(self_pid) - 2, int(self_pid) + 2)):
                        output += f'PID: {pid:<8}\t path:/proc/{pid:<8}\t[!] {get_color("隐藏 pid")}\n'
            except:
                pass

        get_output(info, output)

    def check_exe(self):
        if self.ps.keys():
            info = get_color('命令替换排查', 'green') + '\n可能会有部分误判，可以在 data/info_proc.json 自定义添加规则 "true_exe" : "exe"'
            output = ''

            result = exec_command(self.client, f'ls -al /proc/*/exe 2>/dev/null')
            if result['status'] and result['result']:
                try:
                    group = re.findall(r'.*/proc/(\d+)/exe -> (.*)', result['result'])
                    for item in group:
                        pid = item[0]
                        true_exe = Path(item[1]).name  # exe 真实指向命令
                        exe = self.ps[int(pid)]['exe']

                        if (true_exe != exe) and (((true_exe in check_proc) and (exe not in check_proc[true_exe])) or (true_exe not in check_proc)):
                            output += f'PID: {pid:<8}\ttrue_exe: {true_exe:<20}\texe: {exe:<20}\t[!] {get_color("命令被替换", "red")}\n'
                except:
                    pass

            get_output(info, output)

    def check_mount(self):
        info = get_color('mount 挂载进程排查', 'green')
        output = ''

        result = exec_command(self.client, f'cat /proc/mounts')
        if result['status'] and result['result']:
            try:
                for pid in re.findall(r'/proc/(\d+)', result['result']):
                    output += f'{"path: /proc/"  + pid:<50}\t[!] {get_color("mount挂载后门", "red")}\n'
            except:
                pass
        get_output(info, output)
