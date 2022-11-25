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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Jupyter.unauth import unauth_scan

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

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.jupyter_unauthorized_scan, url=url)
        ]

Jupyter.jupyter_unauthorized_scan = unauth_scan

jupyter = Jupyter()
