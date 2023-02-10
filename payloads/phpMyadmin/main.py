#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
PhpMyAdmin 是一个用 PHP 编写的免费软件工具, 旨在通过 Web 处理 MySQL 的管理
    phpMyadmin扫描类: 
        1. phpmyadmin 4.8.1 远程文件包含
            CVE-2018-12613
                Payload: https://vulhub.org/#/environments/phpmyadmin/CVE-2018-12613/

        2. Phpmyadmin Scripts/setup.php 反序列化
            WooYun-2016-199433
                Payload: https://vulhub.org/#/environments/phpmyadmin/WooYun-2016-199433/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.phpMyadmin.cve_2018_12613 import cve_2018_12613_scan
from payloads.phpMyadmin.wooyun_2016_199433 import wooyun_2016_199433_scan

class phpMyadmin():
    def __init__(self):
        self.app_name = 'phpMyadmin'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cve_2018_12613_scan, clients=clients),
            thread(target=self.wooyun_2016_199433_scan, clients=clients)
        ]

phpMyadmin.cve_2018_12613_scan = cve_2018_12613_scan
phpMyadmin.wooyun_2016_199433_scan = wooyun_2016_199433_scan

phpmyadmin = phpMyadmin()
