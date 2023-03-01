#!/usr/bin/env python3
# -*- coding:utf-8 -*-

unauth_payloads = [
    {'path': ''},
    {'path': 'cluster'},
    {'path': 'cluster/cluster'},
    {'path': 'cluster/nodes'},
    {'path': 'cluster/nodelabels'},
    {'path': 'cluster/apps'},
    {'path': 'cluster/scheduler'},
]

def unauth_scan(clients):
    ''' YARN默认开放REST API, 允许用户直接通过API进行相关的应用创建、任务提交执行等操作, 
        如果配置不当, 将会导致REST API未授权访问, 攻击者可利用其执行远程命令
    '''
    client = clients.get('reqClient')

    vul_info = {
        'app_name': 'ApacheHadoop',
        'vul_type': 'unAuthorized',
        'vul_id': 'ApacheHadoop-unAuth',
    }
    
    for payload in unauth_payloads:
        path = payload['path']

        res = client.request(
            'get',
            path,
            vul_info=vul_info
        )
        if res is None:
            continue

        if ((
                'parseHadoopID' in res.text
                and 'renderHadoopDate' in res.text
                and 'parseHadoopProgress' in res.text)
            or (
                'src="/static/hadoop-st.png"' in res.text
                and 'href="/jmx?qry=Hadoop:*"' in res.text
                and 'org.apache.hadoop.yarn.server.resourcemanager' in res.text
                and 'Hadoop version' in res.text)
            or (
                '<img src="/static/hadoop-st.png">' in res.text
                and '<a href="/jmx?qry=Hadoop:*">Server metrics</a>' in res.text)
        ):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Exploit': 'https://github.com/vulhub/vulhub/blob/master/hadoop/unauthorized-yarn/exploit.py',
                'Request': res
            }
            return results
    return None
