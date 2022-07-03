#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    XXXXX扫描类: 
        XXXXX 未开启强制路由RCE
            CNVD-2018-24942
file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep

class 1():                                              # ! 1: 类名(例如 ThinkPHP)
    ''' 标有数字的地方都需要自己填写 '''
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = '2'                             # ! 2: 漏洞框架/应用程序/CMS等(例如 thinkphp)
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.3_payloads = [                             # ! 3: Payload的名称(例如 cnvd_2018_24942_payloads)
            {
                'path': '4',                            # ! 4: url路径(例如/admin/login)
                'data': '5',                            # ! 5: POST数据, 没有的话可以不写
                'headers': head.merge(self.headers, {}) # ! 6: Headers请求头, 填在{}里面, 字典形式; 没有的话可以不写, 不写的话将使用默认请求头; 如果存在同名的请求头, 则会覆盖掉原来的
            },
        ]

    def 7_scan(self, url):                              # ! 7: POC的名称(例如 cnvd_2018_24942_scan)
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = '8'                      # ! 8: 漏洞类型(例如 RCE)
        vul_info['vul_id'] = '9'                        # ! 9: 漏洞编号(例如 CNVD-2018-24942)
        vul_info['vul_method'] = '10'                   # ! 10: 请求方式(例如 GET)

        for payload in range(len(self.3_payloads)):     # ! 3: 同上, Payload的名称
            path = self.3_payloads[payload]['path']     # ! 3: 同上, Payload的名称
            data = self.3_payloads[payload]['data']     # ! 3: 同上, Payload的名称
            headers = self.3_payloads[payload]['headers']   # ! 3: 同上, Payload的名称
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
            vul_info['target'] = target

            try:
                if payload == 0:                            # * 当payload为第1个时, 执行xxx操作
                    res = requests.11(                      # ! 11: 请求方式(例如 get)
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                elif payload == 1:                          # * 当payload为第2个时, 执行xxx操作
                    res = requests.11(                      # ! 11: 请求方式(例如 get)
                        target, 
                        timeout=self.timeout, 
                        headers=headers,
                        data=data, 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )

                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            '''!!!
                可以自定义results中的信息, 格式:
                    标题: 值(str/list/dict)
                        str类型: key: value的格式进行显示
                        list类型: 会以key: value value value ...的格式进行显示
                        dict类型: 会以↓的格式进行显示
                                dict:
                                    key1: value1
                                    key2: value2
                                    ...
            '''
            if ('12'):               # ! 12: 判断扫描结果
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Data': data,
                        'Cookie': 'xxx',
                        'Headers': headers
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.6_scan, url=url)                  # ! 6: 同上, POC的名称
        ]

13 = 1()                                                         # ! 1: 同上, 类名

'''
    # ! 13: 对象名称
    # ! 需要在vulcat/lib/initial/config.py加入对象名称, 找到以下代码并继续添加
                                                        app_list = ['alidruid', 'airflow', 'apisix', 'cisco', 'django', 'fastjson']
    # ! 然后在vulcat/lib/core/coreScan.py引入POC, 引入方式为
                                                        from payloads.文件名 import 对象名称
    # ! 引入完成后, 自定义POC就成功了, 可以运行vulcat试试效果
'''