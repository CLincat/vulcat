#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Node-RED是一种编程工具, 事件驱动应用程序的低代码编程, 用于以新颖有趣的方式将硬件设备、API和在线服务连接在一起: https://nodered.org/
    Node-RED扫描类: 
        1. Node-RED 任意文件读取
            CVE-2021-3223
                Payload: https://blog.csdn.net/weixin_51387754/article/details/121532015

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.NodeRED.cve_2021_3223 import cve_2021_3223_scan

class NodeRED():
    def __init__(self):
        self.app_name = 'Node-RED'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2021_3223_scan, clients=clients)
        ]

NodeRED.cve_2021_3223_scan = cve_2021_3223_scan

nodered = NodeRED()
