#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
JBOSS未授权访问
    暂无编号
        Payload: https://codeantenna.com/a/vUzclyNJBg

在默认情况下 无需账密就可以直接访问管理控制台
    进而导致网站信息泄露、服务器被上传shell等，最终网站被攻陷
'''

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        self.payloads = [
            {'path': ''},
            {'path': 'jmx-console/'},
            {'path': 'web-console/'},
        ]
    
    def POC(self, clients):
        client = clients.get('reqClient')
        
        vul_info = {
            'app_name': 'JBoss',
            'vul_type': 'unAuth',
            'vul_id': 'jboss-unauthorized',
        }

        for payload in self.payloads:
            path = payload['path']

            res = client.request(
                'get',
                path,
                vul_info=vul_info
            )
            if res is None:
                continue

            if (('JBoss Management' in res.text
                    and '<li><a href="/jmx-console/">JMX Console</a></li>' in res.text
                    and '<li><a href="/web-console/">JBoss Web Console</a></li>' in res.text)
                
                # * jxm-console/
                or ('<title>JBoss JMX Management Console</title>' in res.text
                    and 'ObjectName Filter' in res.text
                    and '<h2 class=\'DomainName\'>JMImplementation</h2>' in res.text
                )
                
                # * web-console/
                or ('<title>Administration Console</title>' in res.text
                    and '<frame id="right" name="right" src="ServerInfo.jsp" >' in res.text
                    and '<p>Please use a frame-capable browser.</p>' in res.text
                )
            ):
                results = {
                    'Target': res.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Vuln-Tool': 'https://github.com/joaomatosf/jexboss',
                    'Request': res
                }
                return results
        return None
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
