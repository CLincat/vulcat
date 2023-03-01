#!/usr/bin/env python3
# -*- coding:utf-8 -*-

''' # ! 由于该POC数据包过多, 只有在指纹识别为Grafana时才会进行扫描, 否则vulcat不会使用该POC

    Grafana扫描类: 
        Grafana 8.x 插件模块文件路径遍历
            CVE-2021-43798
                Payload: https://vulhub.org/#/environments/grafana/CVE-2021-43798/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Grafana.cve_2021_43798 import cve_2021_43798_scan

class Grafana():
    def __init__(self):
        self.app_name = 'Grafana'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cve_2021_43798_scan, clients=clients)
        ]

grafana = Grafana()
