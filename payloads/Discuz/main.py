#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Discuz!论坛(BBS)是一个采用PHP和MySQL等其他多种数据库构建的性能优异、功能全面、安全稳定的社区论坛平台: https://discuz.dismall.com
    Discuz扫描类: 
        1. Discuz 全局变量防御绕过导致代码执行
            wooyun-2010-080723
                Payload: https://vulhub.org/#/environments/discuz/wooyun-2010-080723/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Discuz.wooyun_2010_080723 import wooyun_2010_080723_scan

class Discuz():
    def __init__(self):
        self.app_name = 'Discuz'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=wooyun_2010_080723_scan, clients=clients)
        ]

discuz = Discuz()
