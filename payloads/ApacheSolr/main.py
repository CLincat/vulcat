#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheSolr扫描类: 
        1. Solr SSRF/任意文件读取
            CVE-2021-27905
                Payload: https://vulhub.org/#/environments/solr/Remote-Streaming-Fileread/
                         https://www.freebuf.com/vuls/279278.html

        2. Solr 远程命令执行
            CVE-2017-12629
                Payload: https://vulhub.org/#/environments/solr/CVE-2017-12629-RCE/

        3. Solr Velocity 注入远程命令执行
            CVE-2019-17558
                Payload: https://vulhub.org/#/environments/solr/CVE-2019-17558/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ApacheSolr.tool_enable import enable
from payloads.ApacheSolr.cve_2017_12629 import cve_2017_12629_scan
from payloads.ApacheSolr.cve_2019_17558 import cve_2019_17558_scan
from payloads.ApacheSolr.cve_2021_27905 import cve_2021_27905_scan

class Solr():
    def __init__(self):
        self.app_name = 'ApacheSolr'

        self.db_name = ''
        self.RemoteStreaming = False
        self.params = False

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2017_12629_scan, clients=clients),
            thread(target=self.cve_2019_17558_scan, clients=clients),
            thread(target=self.cve_2021_27905_scan, clients=clients),
        ]

Solr.enable = enable
Solr.cve_2017_12629_scan = cve_2017_12629_scan
Solr.cve_2019_17558_scan = cve_2019_17558_scan
Solr.cve_2021_27905_scan = cve_2021_27905_scan

solr = Solr()