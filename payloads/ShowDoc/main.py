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

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.ShowDoc.cnvd_2020_26585 import cnvd_2020_26585_scan

class ShowDoc():
    def __init__(self):
        self.app_name = 'ShowDoc'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cnvd_2020_26585_scan, clients=clients)
        ]

ShowDoc.cnvd_2020_26585_scan = cnvd_2020_26585_scan

showdoc = ShowDoc()
