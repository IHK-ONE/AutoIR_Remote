from core.functions import *

'''
# FileAnalysis 恶意文件检测
  1./usr/bin 检测
  2.系统可执行文件扫描
  3./tmp 临时目录文件扫描
  4.用户目录文件扫描
  5.可疑隐藏文件扫描
  6.web root webshell 扫描
'''

check_bin_json = json.load(open('data/info_bin.json'))


class FileAnalysis:
    def __init__(self, client):
        self.client = client
        self.path = ''

        self.check_bin()
        self.check_tmp()
        self.check_webshell()

    def check_bin(self):
        info = get_color('/usr/bin 排查', 'green') + '\n排查并不准确，建议下载对应系统参考 readme.md 使用 dump_bin_info.py 进行 dump'
        output = ''

        result = exec_command(self.client, 'ls -alt /usr/bin')
        if result['status'] and result['result']:
            current_bin = []
            for file in get_file_list(result['result']).values():
                filename = file['filename']
                owner = file['owner']
                group = file['group']
                perm = file['perm']
                time = file['time']
                link = ''
                current_bin.append([filename, time])

                if '->' in filename:
                    link = filename.split(' -> ')[1]
                    filename = filename.split(' -> ')[0]

                check_out = []
                if filename in check_bin_json:
                    if perm != check_bin_json[filename]['perm']:
                        check_out.append('权限异常')
                    if owner != check_bin_json[filename]['owner'] or group != check_bin_json[filename]['group']:
                        check_out.append('所属异常')
                    if link != check_bin_json[filename]['link']:
                        check_out.append('恶意链接')
                else:
                    check_out.append("不常见命令")

                if check_out:
                    output += f"file: {filename:<50}\tperm: {perm:<10}\towner: {owner:<5}\tgroup: {group:<5}\t[!] {get_color(', '.join(check_out), 'red')}\n"

            get_output(info, output)
            # 最近修改的文件
            info = get_color('/usr/bin 最近修改', 'green')
            output = ''.join([f'file: {item[-1]:<20}\ttime: {item[-2]:<40}\t[!] {get_color("最近修改的命令")}\n' for item in current_bin[:5]])
            get_output(info, output)

        # 文件类型排查
        info = get_color('/usr/bin 文件类型排查', 'green') + '\n排查并不准确，建议下载对应系统参考 readme.md 使用 dump_bin_info.py 进行 dump'
        output = ''
        result = exec_command(self.client, 'find /usr/bin -type f -exec file {} + 2>/dev/null')
        if result['status'] and result['result']:
            for line in result['result'].splitlines():
                file_path, file_type = line.split(':', 1)
                file_type = file_type.split(',')[0].strip()
                if 'ELF' in file_type:
                    file_type = 'ELF'
                if Path(file_path).name in check_bin_json:
                    if check_bin_json[Path(file_path).name].get('type') != file_type:
                        output += f'file path: {file_path:<60}\tfile type: {file_type:<40}\t[!] {get_color("文件类型错误", "red")}\n'
            get_output(info, output)

    def check_tmp(self):
        info = get_color('/tmp 目录排查', 'green')

        result = exec_command(self.client, 'find /tmp -type f 2>/dev/null')
        if result['status'] and result['result']:
            output = ''.join([f'file path: {item.strip():<50}\t[!] {get_color("/tmp 目录下可疑文件")}\n' for item in result['result'].splitlines()])
            get_output(info, output)

    def is_safe_path(basedir, path):
        try:
            parts = re.split(r'[\\/]+', path)
            for part in parts:
                if part.strip() == '.':
                    return False
        except:
            return True
        return True

    def check_webshell(self):
        info = get_color('webroot webshell分析', 'green')
        output = ''
        path = '/var/www/html'
        check = input(f'请输入 webroot 绝对路径，输入 [Enter] 则为默认 {path}: ')
        if check.strip():
            path = check.strip()

        result = exec_command(self.client, f'find {path} -type f 2>/dev/null')
        if result['status'] and result['result']:
            exec_command(self.client, f'cd {path} && tar -zcvf /tmp/webroot.tar.gz .*')
            self.path = f'downloads\\{get_time_path()}'
            os.makedirs(self.path, exist_ok=True)
            sftp_download(self.client, '/tmp/webroot.tar.gz', f'{self.path}/webroot.tar.gz')

            with tarfile.open(f'{self.path}/webroot.tar.gz', 'r:gz') as tar:
                for member in tar.getmembers():
                    member_path = os.path.join(self.path, member.name)
                    if self.is_safe_path(member_path):
                        tar.extract(member, self.path)
                    else:
                        server_path = path + '/' + member.name.replace('\\', '/')
                        output += f'file path: {server_path:<60}\t[!] {get_color("路径遍历已拦截", "red")}\n'
            result = subprocess.run([f'extensions\\HeMa\\hm.exe', 'scan', f'{self.path}'], capture_output=True,text=True, encoding='utf-8', errors='ignore')

            count = 0
            for line in result.stdout.splitlines():
                if "总计" in line:
                    count = int(line.replace(' ', '').split('|')[-2])
            if count:
                with open(f"extensions\\HeMa\\result.csv", 'r', encoding='utf-8', errors='ignore') as csvfile:
                    csv_reader = csv.reader(csvfile, delimiter=',')
                    next(csv_reader, None)  # 跳过表头
                    for row in csv_reader:
                        suggestion, local_path = row[1], row[2]
                        server_path = local_path.replace(self.path, path.strip()).replace('\\', '/')
                        output += f'file path: {server_path:<50}\tmd5: {hashlib.md5(open(local_path, "rb").read()).hexdigest()}\t[!] {get_color("webroot 可疑文件 " + suggestion, "red")}\n'
                get_output(info, output)
