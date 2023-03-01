#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Ueditor扫描类: 
        ueditor编辑器 SSRF漏洞
            暂无编号
                Payload: https://baizesec.github.io/bylibrary/%E6%BC%8F%E6%B4%9E%E5%BA%93/02-%E7%BC%96%E8%BE%91%E5%99%A8%E6%BC%8F%E6%B4%9E/Ueditor/Ueditor%E7%BC%96%E8%BE%91%E5%99%A81.4.3.3%E7%89%88%E6%9C%ACssrf%E6%BC%8F%E6%B4%9E/
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Ueditor.ssrf import ssrf_scan

class Ueditor():
    def __init__(self):
        self.app_name = 'Ueditor'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=ssrf_scan, clients=clients)
        ]

ueditor = Ueditor()
