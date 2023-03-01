#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Fastjson扫描类: 
        1. Fastjson <=1.2.47 反序列化
            CNVD-2019-22238
                Payload: https://vulhub.org/#/environments/fastjson/1.2.47-rce/
            
        2. Fastjson <= 1.2.24 反序列化
            CNVD-2017-02833
            CVE-2017-18349
                Payload: https://vulhub.org/#/environments/fastjson/1.2.24-rce/

        3. Fastjson <= 1.2.62 反序列化
            暂无编号
                Payload: https://github.com/zhzyker/exphub/blob/master/fastjson/fastjson-1.2.62_rce.py
                         https://cloud.tencent.com/developer/article/1593614

        4. Fastjson <= 1.2.66 反序列化
            暂无编号
                Payload: https://cloud.tencent.com/developer/article/1906247

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Fastjson.cnvd_2017_02833 import cnvd_2017_02833_scan
from payloads.Fastjson.cnvd_2019_22238 import cnvd_2019_22238_scan
from payloads.Fastjson.rce_1_2_62 import rce_1_2_62_scan
from payloads.Fastjson.rce_1_2_66 import rce_1_2_66_scan

class Fastjson():
    def __init__(self):
        self.app_name = 'Fastjson'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=cnvd_2017_02833_scan, clients=clients),
            thread(target=cnvd_2019_22238_scan, clients=clients),
            thread(target=rce_1_2_62_scan, clients=clients),
            thread(target=rce_1_2_66_scan, clients=clients),
        ]

fastjson = Fastjson()