#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool import check
from time import sleep
import re

3_payloads = [                                  # ! 3: Payload的名称(例如 cnvd_2018_24942_payloads)
    {
        'path': '4',                            # ! 4: url路径(例如/admin/login)
        'data': '5',                            # ! 5: POST数据, 没有的话可以不写
    },
]

def 6_scan(clients):                            # ! 6: POC的名称(例如 cnvd_2018_24942_scan)
    '''  '''
    client = clients.get('reqClient')           # todo 使用的中转, reqClient是requests的中转
    # hackClient = clients.get('hackClient')      # todo 使用的中转, hackClient是HackRequests的中转
    
    vul_info = {
        'app_name': '',
        'vul_type': '7',                        # ! 7: 漏洞类型(例如 RCE)
        'vul_id': '8',                          # ! 8: 漏洞编号(例如 CNVD-2018-24942)
    }
    
    headers = {}                                # ! 9. 如果该漏洞需要特殊的Headers,例如 User-Agent:Nacos-Server, 则需要填写, 没有的话就不用填

    for payload in 3_payloads:                  # ! 3: 同上, Payload的名称
        path = payload['path']
        data = payload['data']

        res = client.request(
            'get',                              # ! 10: 请求方式, 例如get, 不区分大小写
            path,                               # ! 11: 路径, 注意 “只要路径”, 不需要添加http://xxx.com
            data=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        # todo 判断
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
                    Response类型: 会以一个http数据包的格式进行显示
        '''
        if ('12'):               # ! 12: 判断扫描结果
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Payload': {
                    'Url': res.url,
                    'Path': path,
                    'Headers': headers,
                    'Cookie': 'XXX'
                },
                'Request': res                  # * 会输出一个http数据包
            }
            return results
    return None
