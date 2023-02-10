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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Jupyter.unauth import unauth_scan

class Jupyter():
    def __init__(self):
        self.app_name = 'Jupyter'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.unauth_scan, clients=clients)
        ]

Jupyter.unauth_scan = unauth_scan

jupyter = Jupyter()
