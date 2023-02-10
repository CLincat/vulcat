#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Yonyou扫描类: 
        1. 用友NC BeanShell远程命令执行漏洞
            CNVD-2021-30167
                Payload: https://mp.weixin.qq.com/s/XivX5eWGxYoUzpfhWDuNCw

        2. 用友ERP-NC NCFindWeb接口任意文件读取/下载/目录遍历
            暂无编号

        3. 用友U8 OA getSessionList.jsp 敏感信息泄漏
            暂无编号
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

        4. 用友U8 OA test.jsp SQL注入
            暂无编号
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004

        5. 用友GRP-U8 Proxy SQL注入 
            CNNVD-201610-923
                Payload: https://blog.csdn.net/qq_41617034/article/details/124268004


'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.Yonyou.cnnvd_201610_923 import cnnvd_201610_923_scan
from payloads.Yonyou.cnvd_2021_30167 import cnvd_2021_30167_scan
from payloads.Yonyou.nc_fileread import nc_fileRead_scan
from payloads.Yonyou.u8_oa_getsession import u8_oa_getsession_scan
from payloads.Yonyou.u8_oa_test_sqlinject import u8_oa_test_sqlinject_scan

class Yonyou():
    def __init__(self):
        self.app_name = 'Yonyou'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=self.cnnvd_201610_923_scan, clients=clients),
            thread(target=self.cnvd_2021_30167_scan, clients=clients),
            thread(target=self.yonyou_nc_fileRead_scan, clients=clients),
            thread(target=self.yonyou_u8_oa_getsession_scan, clients=clients),
            thread(target=self.yonyou_u8_oa_test_sqlinject_scan, clients=clients),
        ]

Yonyou.cnnvd_201610_923_scan = cnnvd_201610_923_scan
Yonyou.cnvd_2021_30167_scan = cnvd_2021_30167_scan
Yonyou.yonyou_nc_fileRead_scan = nc_fileRead_scan
Yonyou.yonyou_u8_oa_getsession_scan = u8_oa_getsession_scan
Yonyou.yonyou_u8_oa_test_sqlinject_scan = u8_oa_test_sqlinject_scan

yonyou = Yonyou()