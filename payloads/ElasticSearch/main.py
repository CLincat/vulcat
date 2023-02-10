#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ElasticSearch扫描类: 
        1. ElasticSearch 命令执行
            CVE-2014-3120
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2014-3120/

        2. ElasticSearch Groovy 沙盒绕过 && 代码执行漏洞
            CVE-2015-1427
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2015-1427/

        3. ElasticSearch 目录穿越
            CVE-2015-3337
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2015-3337/

        4. ElasticSearch 目录穿越
            CVE-2015-5531
                Payload: https://vulhub.org/#/environments/elasticsearch/CVE-2015-5531/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''
        #  Elasticsearch写入webshell
        #   WooYun-2015-110216

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ElasticSearch.cve_2014_3120 import cve_2014_3120_scan
from payloads.ElasticSearch.cve_2015_1427 import cve_2015_1427_scan
from payloads.ElasticSearch.cve_2015_3337 import cve_2015_3337_scan
from payloads.ElasticSearch.cve_2015_5531 import cve_2015_5531_scan

class ElasticSearch():
    def __init__(self):
        self.app_name = 'ElasticSearch'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2014_3120_scan, clients=clients),
            thread(target=self.cve_2015_1427_scan, clients=clients),
            thread(target=self.cve_2015_3337_scan, clients=clients),
            thread(target=self.cve_2015_5531_scan, clients=clients)
        ]

ElasticSearch.cve_2014_3120_scan = cve_2014_3120_scan
ElasticSearch.cve_2015_1427_scan = cve_2015_1427_scan
ElasticSearch.cve_2015_3337_scan = cve_2015_3337_scan
ElasticSearch.cve_2015_5531_scan = cve_2015_5531_scan

elasticsearch = ElasticSearch()
