#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Spring扫描类: 
        1. Spring Framework RCE(Spring core RCE)
            CVE-2022-22965
            Payload: https://vulhub.org/#/environments/spring/CVE-2022-22965/

        2. Spring Boot Actuator Log View 文件读取/文件包含/目录遍历
            CVE-2021-21234
                Payload: https://bbs.zkaq.cn/t/5736.html

        3. Spring Cloud Config Server目录遍历
            CVE-2020-5410
                Payload: https://bbs.zkaq.cn/t/5736.html

        4. Spring Cloud Function SpEL 远程代码执行
            CVE-2022-22963
                Payload: https://vulhub.org/#/environments/spring/CVE-2022-22963/
        
        5. Spring Cloud Gateway SpEl 远程代码执行
            CVE-2022-22947
                Payload: https://vulhub.org/#/environments/spring/CVE-2022-22947/

        6. Spring Security OAuth2 远程命令执行
            CVE-2016-4977
                Payload: https://vulhub.org/#/environments/spring/CVE-2016-4977/

        7. Spring Data Rest 远程命令执行
            CVE-2017-8046
                Payload: https://vulhub.org/#/environments/spring/CVE-2017-8046/

        8. Spring Data Commons 远程命令执行
            CVE-2018-1273
                Payload: https://vulhub.org/#/environments/spring/CVE-2018-1273/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Spring.cve_2016_4977 import cve_2016_4977_scan
from payloads.Spring.cve_2017_8046 import cve_2017_8046_scan
from payloads.Spring.cve_2018_1273 import cve_2018_1273_scan
from payloads.Spring.cve_2020_5410 import cve_2020_5410_scan
from payloads.Spring.cve_2021_21234 import cve_2021_21234_scan
from payloads.Spring.cve_2022_22947 import cve_2022_22947_scan
from payloads.Spring.cve_2022_22963 import cve_2022_22963_scan
from payloads.Spring.cve_2022_22965 import cve_2022_22965_scan

class Spring():
    def __init__(self):
        self.app_name = 'Spring'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2016_4977_scan, clients=clients),
            thread(target=self.cve_2017_8046_scan, clients=clients),
            thread(target=self.cve_2018_1273_scan, clients=clients),
            thread(target=self.cve_2020_5410_scan, clients=clients),
            thread(target=self.cve_2021_21234_scan, clients=clients),
            thread(target=self.cve_2022_22947_scan, clients=clients),
            thread(target=self.cve_2022_22963_scan, clients=clients),
            thread(target=self.cve_2022_22965_scan, clients=clients),
        ]

Spring.cve_2016_4977_scan = cve_2016_4977_scan
Spring.cve_2017_8046_scan = cve_2017_8046_scan
Spring.cve_2018_1273_scan = cve_2018_1273_scan
Spring.cve_2020_5410_scan = cve_2020_5410_scan
Spring.cve_2021_21234_scan = cve_2021_21234_scan
Spring.cve_2022_22947_scan = cve_2022_22947_scan
Spring.cve_2022_22963_scan = cve_2022_22963_scan
Spring.cve_2022_22965_scan = cve_2022_22965_scan

spring = Spring()
