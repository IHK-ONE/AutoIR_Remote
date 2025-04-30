from core.functions import *


def RookitUpload(client):
    sftp_upload(client, 'extensions/rkhunter.gz', '/tmp/rkhunter.gz')
    result = exec_command(client, 'cd /tmp && tar -xf /tmp/rkhunter.gz && cd /tmp/rkhunter-1.4.6 && bash installer.sh --install')

    if result['status'] and result['result']:
        if "complete" in result['result']:
            print(f'[success] {get_color("rkhunter rookit检测工具上传安装成功，需要手动执行命令", "green")}: \n\trkhunter --check')
