#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Jupyter Notebook (此前被称为 IPython notebook) 是一个交互式笔记本, 支持运行 40 多种编程语言
    Jupyter扫描类: 
        Jupyter 未授权访问
            暂无编号
                Payload: https://vulhub.org/#/environments/jupyter/notebook-rce/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep

class Jupyter():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Jupyter'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.jupyter_unauthorized_payloads = [
            {
                'path': 'terminals/0',
                'data': ''
            },
            {
                'path': '',
                'data': ''
            }
        ]

    def jupyter_unauthorized_scan(self, url):
        ''' 如果管理员没有为Jupyter Notebook配置密码, 将导致未授权访问, 
            游客可在其中创建一个console并执行任意Python代码和命令
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'unAuthorized'
        vul_info['vul_id'] = 'jupyter-unauthorized'
        vul_info['vul_method'] = 'GET'

        for payload in self.jupyter_unauthorized_payloads:
            path = payload['path']
            target = url + path

            vul_info['path'] = path
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers,
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

            if ((('<body class="terminal-app' in res.text)
                    and ('data-ws-path="terminals/websocket/0"' in res.text)
                    and ('terminal/js/main.min.js' in res.text))
                or (('data-terminals-available="True"' in res.text)
                    and ('li role="presentation" id="new-terminal"' in res.text))
            ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.jupyter_unauthorized_scan, url=url)
        ]

jupyter = Jupyter()
