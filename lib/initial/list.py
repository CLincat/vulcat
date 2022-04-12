#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import color
import sys

def list():
    ''' 显示漏洞列表 '''
    vul_list = ''
    vul_list += '+' + ('-'*15) + '+' + ('-'*18) + '+' + ('-'*12) + '+' + ('-'*10) + '+' + ('-'*60) + '+\n'

    for vul in vul_info:
        for info in vul_info[vul]:
            vul_list += '| {}|'.format(vul.ljust(14))
            vul_list += ' {}|'.format(info['vul_id'].ljust(17))
            vul_list += ' {}|'.format(info['type'].ljust(11))
            vul_list += ' {}|'.format(info['method'].ljust(9))
            vul_list += ' {}\t|'.format(info['description'].ljust(45))
            vul_list += '\n'
        vul_list += '+' + ('-'*15) + '+' + ('-'*18) + '+' + ('-'*12) + '+' + ('-'*10) + '+' + ('-'*60) + '+\n'

    print(color.cyan(vul_list))
    sys.exit(0)

vul_info = {
    'Target': [
        {
            'vul_id': 'Vul_id',
            'type': 'Type',
            'method': 'Method',
            'description': 'Description\t'
        }
    ],
    'AlibabaDruid': [
        {
            'vul_id': 'None',
            'type': 'unAuth',
            'method': 'GET',
            'description': '阿里巴巴Druid未授权访问'
        }
    ],
    'AlibabaNacos': [
        {
            'vul_id': 'CVE-2021-29441',
            'type': 'unAuth',
            'method': 'GET/POST',
            'description': '阿里巴巴Nacos未授权访问'
        }
    ],
    'ApacheTomcat': [
        {
            'vul_id': 'CVE-2017-12615',
            'type': 'FileUpload',
            'method': 'PUT',
            'description': 'PUT方法任意文件写入'
        }
    ],
    'Cisco': [
        {
            'vul_id': 'CVE-2020-3580',
            'type': 'XSS',
            'method': 'POST',
            'description': '思科ASA/FTD软件跨站脚本攻击'
        }
    ],
    'Django': [
        {
            'vul_id': 'CVE-2017-12794',
            'type': 'XSS',
            'method': 'GET',
            'description': 'Django debug page XSS跨站脚本攻击'
        },
        {
            'vul_id': 'CVE-2019-14234',
            'type': 'SQLinject',
            'method': 'GET',
            'description': 'Django JSONfield sql注入'
        }
    ],
    # 'Keycloak': [
    #     {
    #         'vul_id': 'CVE-2020-10770',
    #         'type': 'SSRF',
    #         'method': 'GET',
    #         'description': '使用request_uri参数调用未经验证的URL'
    #     }
    # ],
    'Spring': [
        {
            'vul_id': 'CVE-2022-22965',
            'type': 'RCE',
            'method': 'POST',
            'description': 'Spring Framework远程代码执行'
        }
    ],
    'ThinkPHP': [
        {
            'vul_id': 'CNVD-2018-24942',
            'type': 'RCE',
            'method': 'GET',
            'description': '未开启强制路由导致RCE'
        },
        {
            'vul_id': 'CNNVD-201901-445',
            'type': 'RCE',
            'method': 'POST',
            'description': '核心类Request远程代码执行'
        }
    ],
    'Weblogic': [
        {
            'vul_id': 'CVE-2020-14750',
            'type': 'unAuth',
            'method': 'GET',
            'description': 'Weblogic权限验证绕过'
        }
    ],
    'Yonyou': [
        {
            'vul_id': 'CNVD-2021-30167',
            'type': 'RCE',
            'method': 'GET',
            'description': '用友NC BeanShell远程命令执行'
        },
        {
            'vul_id': 'None',
            'type': 'FileRead',
            'method': 'GET',
            'description': '用友ERP-NC NCFindWeb接口任意文件读取/下载'
        }
    ]
}

# vul_list = '''
# +------------------------------+---------+---------+-------------------------------+
# | Target    | Vul_id           | Type    | Method  | Description                   |
# +-----------+------------------+---------+---------+-------------------------------+
# | Cisco     | CVE-2020-3580    | XSS     | POST    | 思科ASA/FTD软件XSS漏洞        |
# | ThinkPHP  | CNVD-2018-24942  | RCE     | GET     | 未开启强制路由RCE             |
# | ThinkPHP  | CNNVD-201901-445 | RCE     | POST    | 核心类Request远程代码执行     |
# | XXX       | CVE-XXX-XXX      | RCE     | GET     | XXXXXXX                       |
# +-----------+------------------+---------+---------+-------------------------------+
# | XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX     |
# +--------------------------------------------------------------------------+
# '''