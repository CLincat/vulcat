#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Drupal是使用PHP语言编写的开源内容管理框架(CMF): https://www.drupal.com/ or https://www.drupal.cn/
    Drupal扫描类: 
        1. Drupal Drupalgeddon 2 远程代码执行
            CVE-2018-7600
                Payload: https://vulhub.org/#/environments/drupal/CVE-2018-7600/

        2. Drupal < 7.32 Drupalgeddon SQL 注入
            CVE-2014-3704
                Payload: https://vulhub.org/#/environments/drupal/CVE-2014-3704/

        3. Drupal Core 8 PECL YAML 反序列化任意代码执行
            CVE-2017-6920
                Payload: https://vulhub.org/#/environments/drupal/CVE-2017-6920/

        4. Drupal 远程代码执行
            CVE-2018-7602
                Payload: https://vulhub.org/#/environments/drupal/CVE-2018-7602/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Drupal.tool_get_token import get_form_token
from payloads.Drupal.cve_2014_3704 import cve_2014_3704_scan
from payloads.Drupal.cve_2017_6920 import cve_2017_6920_scan
from payloads.Drupal.cve_2018_7600 import cve_2018_7600_scan
from payloads.Drupal.cve_2018_7602 import cve_2018_7602_scan

class Drupal():
    def __init__(self):
        self.app_name = 'Drupal'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2014_3704_scan, clients=clients),
            thread(target=self.cve_2017_6920_scan, clients=clients),
            thread(target=self.cve_2018_7600_scan, clients=clients),
            thread(target=self.cve_2018_7602_scan, clients=clients)
        ]

Drupal.get_form_token = get_form_token
Drupal.cve_2014_3704_scan = cve_2014_3704_scan
Drupal.cve_2017_6920_scan = cve_2017_6920_scan
Drupal.cve_2018_7600_scan = cve_2018_7600_scan
Drupal.cve_2018_7602_scan = cve_2018_7602_scan

drupal = Drupal()
