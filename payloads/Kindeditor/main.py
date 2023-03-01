#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' 还没写好
KindEditor是一套开源的HTML可视化编辑器
    Kindeditor扫描类: 
        Kindeditor 目录遍历
            CVE-2018-18950
                Payload: https://baizesec.github.io/bylibrary/%E6%BC%8F%E6%B4%9E%E5%BA%93/02-%E7%BC%96%E8%BE%91%E5%99%A8%E6%BC%8F%E6%B4%9E/Kindeditor/KindEditor%203.4.2%263.5.5%E5%88%97%E7%9B%AE%E5%BD%95%E6%BC%8F%E6%B4%9E/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Kindeditor.cve_2018_18950 import cve_2018_18950_scan

class Kindeditor():
    def __init__(self):
        self.app_name = 'Kindeditor'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2018_18950_scan, clients=clients)
        ]

kindeditor = Kindeditor()
