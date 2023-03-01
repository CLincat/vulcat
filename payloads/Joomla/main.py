#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Joomla是一套全球知名的内容管理系统（CMS），使用PHP语言加上MySQL数据库所开发
可以在Linux、Windows、MacOSX等各种不同的平台上运行

    Joomla扫描类: 
        暂无. Joomla提权漏洞 导致RCE
            CVE-2020-11890
                Payload: https://github.com/HoangKien1020/CVE-2020-11890

        2. Joomla3.7 Core com_fields组件SQL注入
            CVE-2017-8917
                Payload: https://blog.csdn.net/BROTHERYY/article/details/109155428

        3. Joomla webservice 接口未授权访问漏洞
            CVE-2023-23752
                Payload: https://xz.aliyun.com/t/12175

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Joomla.cve_2017_8917 import cve_2017_8917_scan
from payloads.Joomla.cve_2023_23752 import cve_2023_23752_scan

class Joomla():
    def __init__(self):
        self.app_name = 'Joomla'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2017_8917_scan, clients=clients),
            thread(target=cve_2023_23752_scan, clients=clients),
        ]

joomla = Joomla()
