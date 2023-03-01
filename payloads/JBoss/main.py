#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
JBoss是一个基于J2EE的开放源代码的应用服务器，代码遵循LGPL许可可以在任何商业应用中免费使用
JBoss是一个管理EJB的容器和服务器，支持EJB 1.1、EJB 2.0和EJB3的规范，
但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或Jetty绑定使用

    JBoss扫描类: 
        1. JBOSS未授权访问
            暂无编号
                Payload: https://codeantenna.com/a/vUzclyNJBg



file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:\Windows\System32\drivers\etc\hosts
'''

# from lib.initial.config import config
from lib.tool.thread import thread
from payloads.JBoss.unauth import unauth_scan

class JBoss():
    def __init__(self):
        self.app_name = 'JBoss'

    def addscan(self, clients, vuln=None):
        if vuln:
            return eval('thread(target={}_scan, clients=clients)'.format(vuln))

        return [
            thread(target=unauth_scan, clients=clients)
        ]

jboss = JBoss()
