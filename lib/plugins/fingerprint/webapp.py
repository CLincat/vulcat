#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    web应用程序/框架 指纹识别
        ...
'''

from lib.initial.config import config
from lib.tool.logger import logger
from lib.tool import check
from thirdparty import requests
from time import sleep
import re

class WebappIdentify():
    def identify(self, url):
        '''
            web应用程序/框架识别
        '''
        try:
            vul_info = {
                'app_name': 'WebApp',
                'vul_id': 'identify'
            }

            new_app_list = []

            res = requests.get(
                url,
                timeout=self.timeout,
                headers=self.headers,
                proxies=self.proxies,
                verify=False
            )
            logger.logging(vul_info, res.status_code, res)                        # * LOG
            res.encoding = 'utf-8'

            for web_fp in self.webapp_fingerprint:
                try:
                    if ((not web_fp['path']) and (not web_fp['data'])):               # * 如果没有特殊路径
                        # * 响应内容 识别
                        for finger in web_fp['fingerprint']:
                            if (re.search(finger, res.text, re.I|re.M|re.U|re.S)):
                                new_app_list.append(web_fp['name'])                   # * 识别出框架, 则添加相应POC
                                continue
                    else:
                        sleep(self.delay)

                        if (web_fp['data']):
                            res2 = requests.post(                                     # * 如果有特殊DATA, 则POST请求
                            url,
                            timeout=self.timeout,
                            headers=self.headers,
                            data=web_fp['data'],
                            proxies=self.proxies,
                            verify=False
                        )
                        else:
                            res2 = requests.get(                                      # * 如果有特殊路径, 则GET请求
                                url + web_fp['path'],
                                timeout=self.timeout,
                                headers=self.headers,
                                proxies=self.proxies,
                                verify=False
                            )
                        logger.logging(vul_info, res2.status_code, res2)              # * LOG
                        res2.encoding = 'utf-8'

                        for finger in web_fp['fingerprint']:
                            if (re.search(finger, res2.text, re.I|re.M|re.U|re.S)):
                                new_app_list.append(web_fp['name'])                   # * 识别出框架, 则添加相应POC
                                continue
                except requests.ConnectTimeout:
                    # logger.info('red_ex', self.lang['core']['web_finger']['web_timeout'])
                    continue
                except requests.ConnectionError:
                    # logger.info('red_ex', self.lang['core']['web_finger']['web_conn_error'])
                    continue
                except KeyboardInterrupt:
                    if self.stop():
                        continue
                    else:
                        self.queue.queue.clear()                                                        # * 清空当前url的扫描队列
                        break                                                                           # * 停止当前url的扫描, 并扫描下一个url
            return set(new_app_list)                                              # * 去重
        except Exception as e:
            logger.info('red_ex', self.lang['core']['web_finger']['web_error'])
            return None

    def __init__(self):
        self.delay = config.get('delay')
        self.lang = config.get('lang')
        self.timeout = config.get('timeout')
        self.headers = config.get('headers')
        self.proxies = config.get('proxies')

        # * webapp指纹库
        self.webapp_fingerprint = [
            {
                'name': 'nacos',
                'path': 'nacos/',
                'data': '',
                'fingerprint': [
                    r'(<title>Nacos</title>).*(<!-- 第三方css开始 -->)'
                ]
            },
            {
                'name': 'nacos',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'(<title>Nacos</title>).*(<!-- 第三方css开始 -->)'
                ]
            },
            {
                'name': 'airflow',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>Airflow - Login</title>',
                    r'<h1 class="text-center login-title">Sign in to Airflow</h1>',
                    r'<title>Airflow 404 = lots of circles</title>',
                    r'<h1>Airflow 404 = lots of circles</h1>'
                ]
            },
            {
                'name': 'airflow',
                'path': 'admin/airflow/login',
                'data': '',
                'fingerprint': [
                    r'<title>Airflow - Login</title>',
                    r'<h1 class="text-center login-title">Sign in to Airflow</h1>',
                    r'<title>Airflow 404 = lots of circles</title>',
                    r'<h1>Airflow 404 = lots of circles</h1>'
                ]
            },
            {
                'name': 'apisix',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'"error_msg":"failed to check token"'
                ]
            },
            {
                'name': 'apisix',
                'path': 'apisix/admin/',
                'data': '',
                'fingerprint': [
                    r'"error_msg":"failed to check token"'
                ]
            },
            {
                'name': 'flink',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'Apache Flink Web Dashboard'
                ]
            },
            {
                'name': 'solr',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'(<html ng-app="solrAdminApp">)|(<h2>SolrCore Initialization Failures</h2>)'
                ]
            },
            {
                'name': 'solr',
                'path': 'solr/',
                'data': '',
                'fingerprint': [
                    r'(<html ng-app="solrAdminApp">)|(<h2>SolrCore Initialization Failures</h2>)'
                ]
            },
            # {
            #     'name': 'struts2',
            #     'path': '',
            #     'data': '',
            #     'fingerprint': [
            #         r''             # * 还没有添加指纹
            #     ]
            # },
            {
                'name': 'tomcat',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>Apache Tomcat/.*</title>'
                ]
            },
            {
                'name': 'tomcat',
                'path': 'qwe/',
                'data': '',
                'fingerprint': [
                    r'<h3>Apache Tomcat/.*</h3>'
                ]
            },
            {
                'name': 'appweb',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>Unauthorized</title>.*shortcut icon.*<h2>Access Error: 401 -- Unauthorized</h2>'
                ]
            },
            {
                'path': '',
                'data': '',
                'name': 'confluence',
                'fingerprint': [
                    r'<title>登录 - Confluence</title>.*confluence-context-path',
                    r'Log In - Confluence.*confluence-context-path'
                ]
            },
            # {
            #     'path': '',
            #     'data': '',
            #     'name': 'cisco',
            #     'fingerprint': [
            #         r''                 # * 还没有添加指纹
            #     ]
            # },
            {
                'name': 'discuz',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title> Discuz! Board  - Powered by Discuz!</title>',
                    r'<title>.*Discuz! Board  - Powered by Discuz!</title>',
                    r'<a href="index\.php">Discuz! Board</a> &raquo; 首页</div>',
                    r'<img src="images/default/logo\.gif" alt="Discuz! Board" border="0" />',
                    r'<p>Powered by <strong><a href="http://www\.discuz\.net" target="_blank">Discuz!</a>'
                ]
            },
            {
                'name': 'django',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'Django administration'
                ]
            },
            {
                'name': 'django',
                'path': 'qwe/',     # * 访问一个不存在的路径时会提示相应信息
                'data': '',
                'fingerprint': [
                    r'You\'re seeing this error because you have.*standard 404 page\.'
                ]
            },
            {
                'name': 'drupal',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'name="Generator" content="Drupal \d \(http(s)?://(w){0,3}\.?drupal\.org\)"',
                    r'data-drupal-link-system-path=".*"',
                    r'jQuery\.extend\(Drupal\.settings, {"basePath',
                    r'There is a security update available for your version of Drupal\. To ensure the security of your server, you should update immediately! See the',
                    r'<span>Powered by <a href="http://drupal\.org">Drupal</a></span>'
                ]
            },
            {
                'name': 'elasticsearch',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'"tagline" : "You Know, for Search"',
                    r'"cluster_name" : "elasticsearch"'
                ]
            },
            {
                'name': 'f5bigip',
                'path': 'tmui/login.jsp',
                'data': '',
                'fingerprint': [
                    r'<title>BIG-IP&reg;.*</title>',
                    r'This BIG-IP system has encountered a configuration problem that may prevent the Configuration utility from functioning properly',
                    r'To prevent adverse effects on the system, F5 Networks recommends that you restrict your',
                    r'if the user has logged out (doesn\'t have a BIGIPAuthCookie)'
                ]
            },
            {
                'name': 'fastjson',
                'path': '',
                'data': '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"abcd","autoCommit":true}}',
                'fingerprint': [
                    r'com\.alibaba\.fastjson\.JSONException:',
                    r'JSON parse error: set property error, autoCommit;'
                ]
            },
            {
                'name': 'jenkins',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>仪表盘 \[Jenkins\]</title>',
                    r'<title>登录 \[Jenkins\]</title>',
                    r'<h1>欢迎来到 Jenkins！</h1>',
                    r'<title>Dashboard \[Jenkins\]</title>',
                    r'<title>Sign in \[Jenkins\]</title>',
                    r'<h1>Welcome to Jenkins!</h1>'
                ]
            },
            # {
            #     'name': 'keycloak',
            #     'path': '',
            #     'data': '',
            #     'fingerprint': [
            #         r''             # * 还没有添加指纹
            #     ]
            # },
            # {
            #     'name': 'kindeditor',     # * POC还没好
            #     'path': 'kindeditor.js',
            #     'data': '',
            #     'fingerprint': [
            #         r'KindEditor - WYSIWYG HTML Editor for Internet'
            #     ]
            # },
            {
                'name': 'mongoexpress',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>.* - Mongo Express</title>',
                    r'<img src=".*/mongo-express-logo\.png"',
                    r'<a class="navbar-brand" href="">Mongo Express</a>',
                    r'<h1 id="pageTitle">Mongo Express</h1>'
                ]
            },
            {
                'name': 'nodejs',
                'path': '/404',
                'data': '',
                'fingerprint': [
                    r'<pre>Cannot GET /.*</pre>'
                ]
            },
            {
                'name': 'nodered',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<script src="red&#x2F;red\.min\.js">',
                    r'<script src="red/red\.min\.js">',
                    r'rel="mask-icon" href="red&#x2F;images&#x2F;node-red-icon-black\.svg"',
                    r'rel="mask-icon" href="red/images/node-red-icon-black\.svg"',
                    r'<title>Node-RED</title>'
                ]
            },
            {
                'name': 'showdoc',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'一个非常适合IT团队的在线API文档、技术文档工具。你可以使用Showdoc来编写在线API文档、技术文档、数据字典、在线手册'
                ]
            },
            {
                'name': 'spring',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'{"_links":{.*health'
                ]
            },
            {
                'name': 'spring',
                'path': 'actuator/',
                'data': '',
                'fingerprint': [
                    r'{"_links":{.*health',
                    r'There was an unexpected error \(type=Not Found, status=\w*\)',
                    r'<h1>Whitelabel Error Page</h1>',
                    r'"message":"No message available".*"path":".*',
                    r'"timestamp":.*"status":404',
                ]
            },
            {
                'name': 'thinkphp',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'十年磨一剑-为API开发设计的高性能框架',
                    r'十年磨一剑 - 为API开发设计的高性能框架',
                    r':\)',
                    r'ThinkPHP.*V.*'
                ]
            },
            {
                'name': 'thinkphp',
                'path': 'qwe/',     # * 访问一个不存在的路径时会提示相应信息
                'data': '',
                'fingerprint': [
                    r'十年磨一剑-为API开发设计的高性能框架',
                    r'十年磨一剑 - 为API开发设计的高性能框架',
                    r':\)',
                    r'ThinkPHP.*V.*'
                ]
            },
            {
                'name': 'ueditor',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'arr\.push(.*欢迎使用ueditor\'.*)',
                    r'<button onclick="getAllHtml()">获得整个html的内容</button>',
                    r'<button onclick=" UE\.getEditor(\'editor\')\.setHide()">隐藏编辑器</button>'
                ]
            },
            {
                'name': 'weblogic',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'Oracle WebLogic Server 管理控制台',
                    r'需要 JavaScript。启用 JavaScript 以便使用 WebLogic 管理控制台。',
                    r'Oracle WebLogic Server Administration Console',
                    r'JavaScript is required\. Enable JavaScript to use WebLogic Administration Console\.',
                    r'Log in to work with the WebLogic Server domain',
                    r'Oracle is a registered trademark of Oracle Corporation and/or its affiliates\.'
                ]
            },
            {
                'name': 'weblogic',
                'path': 'console/',
                'data': '',
                'fingerprint': [
                    r'Oracle WebLogic Server 管理控制台',
                    r'需要 JavaScript。启用 JavaScript 以便使用 WebLogic 管理控制台。',
                    r'Oracle WebLogic Server Administration Console',
                    r'JavaScript is required\. Enable JavaScript to use WebLogic Administration Console\.',
                    r'Log in to work with the WebLogic Server domain',
                    r'Oracle is a registered trademark of Oracle Corporation and/or its affiliates\.'
                ]
            },
            {
                'name': 'webmin',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'You must enter a username and password to login to the server on<strong>\w*</strong>',
                    r'<title>Login to Webmin</title>',
                    r'label aria-label="Webmin" data-container="#content"',
                    r'form id="webmin_search_form" action="/webmin_search\.cgi"',
                    r'Webmin Configuration.*Webmin Servers Index.*Webmin Users',
                    r'a href="/webmin/refresh_modules.cgi" class="navigation_module_trigger"'
                ]
            },
            {
                'name': 'yonyou',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<div class="footer">版权所有.*用友网络科技股份有限公司.*',
                    r'<title>YONYOU NC</title>'
                ]
            },
            # {
            #     'path': 'ueditor/',
            #     'data': '',
            #     'name': 'ueditor',
            #     'fingerprint': [
            #         r'<button onclick="getAllHtml()">获得整个html的内容</button>',
            #         r'<button onclick=" UE\.getEditor(\'editor\').setHide()">隐藏编辑器</button>',
            #         r'arr\.push(.*欢迎使用ueditor\'.*'
            #     ]
            # },
            # {
            #     'path': 'UEditor/',
            #     'data': '',
            #     'name': 'ueditor',
            #     'fingerprint': [
            #         r'<button onclick="getAllHtml()">获得整个html的内容</button>',
            #         r'<button onclick=" UE\.getEditor(\'editor\').setHide()">隐藏编辑器</button>',
            #         r'arr\.push(.*欢迎使用ueditor\'.*'
            #     ]
            # }
        ]

webapp = WebappIdentify()