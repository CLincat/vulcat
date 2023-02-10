#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    web应用程序/框架 指纹识别
        ...
'''

from lib.initial.config import config
from lib.tool.logger import logger
from time import sleep
import re

class WebappIdentify():
    def identify(self, client):
        '''
            web应用程序/框架识别
        '''
        try:
            vul_info = {
                'app_name': 'WebApp',
                'vul_id': 'identify'
            }

            errors = {
                'Timeout': {
                    'text_color': 'red_ex',
                    'text': self.lang['core']['web_finger']['Timeout']
                },
                'Faild': {
                    'text_color': 'red_ex',
                    'text': self.lang['core']['web_finger']['Faild']
                },
                'Error': {
                    'text_color': 'red_ex',
                    'text': self.lang['core']['web_finger']['Error']
                }
            }

            new_app_list = []

            logger.info('yellow_ex', self.lang['core']['web_finger']['start'])

            res = client.request(
                'get',
                '',
                vul_info=vul_info,
                errors=errors
            )

            if res is not None:
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
                                res2 = client.request(                                    # * 如果有特殊DATA, 则POST请求
                                    'post',
                                    '',
                                    data=web_fp['data'],
                                    vul_info=vul_info,
                                )
                            else:
                                res2 = client.request(                                    # * 如果有特殊路径, 则GET请求
                                    'get',
                                    web_fp['path'],
                                    vul_info=vul_info,
                                )

                            if res2 is not None:
                                res2.encoding = 'utf-8'
                                for finger in web_fp['fingerprint']:
                                    if (re.search(finger, res2.text, re.I|re.M|re.U|re.S)):
                                        new_app_list.append(web_fp['name'])                   # * 识别出框架, 则添加相应POC
                                        continue
                    except KeyboardInterrupt:
                        if self.stop():
                            continue
                        else:
                            self.queue.queue.clear()                                                        # * 清空当前url的扫描队列
                            break                                                                           # * 停止当前url的扫描, 并扫描下一个url
                        
            if new_app_list:
                dedup_app_list = set(new_app_list)          # * 去重
                
                logger.info('yellow_ex', self.lang['core']['web_finger']['Find'].format(str(dedup_app_list)))
                return dedup_app_list

            logger.info('yellow_ex', self.lang['core']['web_finger']['NotFind'])
            return None
        except:
            return None
        
    def __init__(self):
        self.delay = config.get('delay')
        self.lang = config.get('lang')

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
                'name': 'apachedruid',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'www\.apache\.org/licenses/LICENSE.*<title>Apache Druid</title>',
                    r'<meta name="description" content="Apache Druid web console">',
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
                'name': 'httpd',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'The requested URL was not found on this server\.',
                    r'You don\'t have permission to access this resource\.',
                    r'The server is temporarily unable to service your request due to maintenance downtime or capacity problems\. Please try again later\.',
                    r'<title>Apache Tomcat/.*</title>',
                    r'<span id="nav-home"><a href="http://tomcat\.apache\.org/">Home</a></span>',
                    r'<p class="copyright">Copyright.*\d{0,4}-\d{0,4} Apache Software Foundation\.  All Rights Reserved</p>',
                    r'These icons were originally made for Mosaic for X.*If you\'d like to contribute additions to this set.*http://httpd\.apache\.org/docs-project',
                    r'<title>Apache2 Debian Default Page: It works</title>.*Apache2 Debian Default Page',
                    r'Apache2 server after installation on Debian systems.*it means that the Apache HTTP server installed',
                    r'The configuration layout for an Apache2 web server installation on Debian systems is as follows:',
                    r'Apache2 package with Debian\. However, check.*existing bug reports'
                ]
            },
            {
                'name': 'skywalking',
                'path': '',
                'data': '',
                'fingerprint': [
                    r"<strong>We're sorry but SkyWalking doesn't work properly without JavaScript enabled\. Please enable it to continue\.</strong>",
                    r"We're sorry but SkyWalking doesn't work properly without JavaScript enabled\."
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
                    r'<title>Apache Tomcat/.*</title>',
                    r'<span id="nav-home"><a href="http://tomcat\.apache\.org/">Home</a></span>',
                    r'<p class="copyright">Copyright.*\d{0,4}-\d{0,4} Apache Software Foundation\.  All Rights Reserved</p>'
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
                'name': 'apacheunomi',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<img src="images/unomi-86x20\.png" alt="Logo Apache Unomi"/>',
                    r'<h1 class="display-5">Welcome to Apache Unomi !</h1>',
                    r'Try Apache Unomi\'s <a href="/tracker/">integrated tracker</a>',
                    r'<p class="lead">Apache Unomi is a Java Open Source customer data platform, a Java server.*visitor privacy rules (such as GDPR)</p>',
                    r'<li>Checkout some cool <a href="http://unomi\.apache\.org/resources\.html" target="_blank">videos & tutorials</a>',
                    r'<li>Read <a href="http://unomi\.apache\.org/manual/latest/index\.html" target="_blank">Apache Unomi\'s manual</a>',
                    r'<li>Try out some <a href="http://unomi\.apache\.org/manual/latest/index\.html#_integration_samples"',
                    r'<li>Join <a href="http://unomi\.apache\.org/community\.html" target="_blank">Apache Unomi\'s mailing lists</a></li>',
                    r'<a class="github-button" href="https://github\.com/apache/incubator-unomi" data-icon="octicon-star"',
                    r'data-show-count="true" aria-label="Star apache/incubator-unomi on GitHub">Star</a>',
                    r'<li>Fork the <a href="https://github\.com/apache/incubator-unomi" target="_blank">code</a> and submit pull',
                    r'<title>Apache Unomi Welcome Page</title>',
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
                'name': 'fastjson',
                'path': '',
                'data': '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"abcd","autoCommit":true}}',
                'fingerprint': [
                    r'com\.alibaba\.fastjson\.JSONException:',
                    r'JSON parse error: set property error, autoCommit;'
                ]
            },
            {
                'name': 'gitea',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>.* - Gitea: Git with a cup of tea</title>',
                    r'Copyright (c) .* The Gitea Authors',
                    r'Gitea 当前版本: .* 页面: <strong>\d*ms</strong> 模板: <strong>\d*ms</strong>',
                    r'Go 语言</a> 支持的平台都可以运行 Gitea，包括 Windows、Mac、Linux 以及 ARM。挑一个您喜欢的就行！',
                    r'<p class="large">.*一个廉价的树莓派的配置足以满足 Gitea 的最低系统硬件要求。最大程度上节省您的服务器资源！.*</p>',
                    r'所有的代码都开源在 <a target="_blank" rel="noopener" href="https://github\.com/go-gitea/gitea/">GitHub</a> 上，赶快加入我们来共同发展这个伟大的项目！还等什么？成为贡献者吧！'
                ]
            },
            {
                'name': 'gitlab',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>GitLab</title>', 
                    r'<meta content="GitLab" property="og:site_name">',
                    r'<meta content="GitLab Community Edition" property="og:description">',
                    r'meta content="GitLab Community Edition" property="twitter:description"',
                    r'meta content="GitLab Community Edition" name="description"',
                    r'<a href="https://about\.gitlab\.com/">About GitLab</a>'
                ]
            },
            {
                'name': 'grafana',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<link rel="mask-icon" href="public/img/grafana_mask_icon\.svg"',
                    r'body class="theme-dark app-grafana',
                    r'public/img/grafana_icon\.svg',
                    r'Loading Grafana.*2\..*grafana.*3\..*4\..*5\.',
                    r'window\.__grafana.*'
                ]
            },
            {
                'name': 'hadoop',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<img src="/static/hadoop-st\.png">',
                    r'<a href="/jmx\?qry=Hadoop:\*">Server metrics</a>',
                    r"'sType':'natural', 'aTargets': \[0\], 'mRender': parseHadoopID",
                    r'<pre>org\.apache\.hadoop\.yarn\.webapp\.WebAppException:'
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
            {
                'name': 'jetty',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<hr><a href="https?://eclipse\.org/jetty">Powered by Jetty:// .{0,30}</a><hr/>',
                    r'<i><small>Powered by Jetty://.{0,30}</small></i>'
                ]
            },
            {
                'name': 'jupyter',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'Jupyter Notebook requires JavaScript',
                    r"<img src='/static/base/images/logo\.png\?v=\d{0,32}' alt='Jupyter Notebook'/>",
                    r'<span id="running_list_info">Currently running Jupyter processes</span>'
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
                'name': 'landray',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'\["sys/ui/extend.{0,50}\.css"\]',
                    r"'lui': 'sys/ui/js'"
                ]
            },
            {
                'name': 'minihttpd',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<address><a href="http://www\.acme\.com/software/mini_httpd/">mini_httpd/.{0,40}</a></address>'
                ]
            },
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
                'name': 'nexus',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>Nexus Repository Manager</title>',
                    r'<title>Sonatype Nexus</title>',
                    r'<meta name="description" content="Nexus Repository Manager"/>',
                    r'<script type="text/javascript">progressMessage(\'Loading nexus-.{0,20}\.js\');</script>',
                    r'<img id="loading-product" src="http.{0,50}/static/rapture/resources/images/loading-product\.png.{0,25}" alt="Nexus Repository Manager"/>',
                    r'You are using a version of Internet Explorer that is not supported\.<br/>See the <a href="http://links\.sonatype\.com/products/nexus/oss/docs/browsers',
                    r"Nexus\.Log\.debug('Initializing UI\.\.\.');",
                    r'<img src="images/header_branding\.png" alt="Sonatype Nexus"/>'
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
                'name': 'phpmyadmin',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<link rel="stylesheet" type="text/css" href="phpmyadmin\.css\.php\?server=1&amp;token=.{32}&amp;nocache=.{0,15}" />',
                    r'<a href="\./url\.php\?url=http%3A%2F%2Fwiki\.phpmyadmin\.net%2F&amp;token=.{32}" target="_blank">',
                    r'<a href="\./url\.php\?url=http%3A%2F%2Fwww\.phpMyAdmin\.net%2F&amp;token=.{32}" target="_blank">',
                    r'<a href="\./url\.php\?url=http%3A%2F%2Fwww\.phpmyadmin\.net%2Fhome_page%2Fimprove\.php&amp;token=.{32}" target="_blank">',
                    r'<a href="\./url\.php\?url=http%3A%2F%2Fwww\.phpmyadmin\.net%2Fhome_page%2Fsupport\.php&amp;token=.{32}" target="_blank">',
                    r'<a href="index\.php\?db=&amp;table=&amp;server=1&amp;target=&amp;token=.{32}" title="打开新 phpMyAdmin 窗口" target="_blank">',
                    r'<img src="themes/dot\.gif" title="打开新 phpMyAdmin 窗口" alt="打开新 phpMyAdmin 窗口" class="icon ic_window-new" />',
                    r'<a href="\./url\.php\?url=https%3A%2F%2Fwww\.phpmyadmin\.net%2F" target="_blank" rel="noopener noreferrer">',
                    r'<link rel="stylesheet" type="text/css" href="phpmyadmin\.css\.php\?nocache=.{0,15}&amp;server=1" />'
                ]
            },
            {
                'name': 'rails',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<title>Ruby on Rails</title>',
                    r'<h1>Yay! You&rsquo;re on Rails!</h1>',
                    r'<strong>Rails version:</strong>.*<br />',
                    r'<strong>Ruby version:</strong>.*(.*)',
                    r'<p><code>Rails\.root: .*</code></p>',
                    r'<li>For more information about routes, please see the Rails guide<a href="http://guides\.rubyonrails\.org/routing\.html">Rails Routing from the Outside In</a>\.</li>',
                    r'<title>RailsFileContent</title>',
                    r'<script src="/assets/.{0,30}\.self-.{64}\.js\?body=1" data-turbolinks-track=".{0,10}"></script>'
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
                'name': 'supervisor',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<link href="stylesheets/supervisor\.css" rel="stylesheet" type="text/css"',
                    r'<img alt="Supervisor status" src="images/supervisor\.gif"',
                    r'<a href="https?://supervisord\.org">Supervisor</a> <span>\d\.\d\.\d</span>'
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
                    r'ThinkPHP.*V.*',
                    r'\d{0,3}载初心不改 - 你值得信赖的PHP框架'
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
                    r'ThinkPHP.*V.*',
                    r'\d{0,3}载初心不改 - 你值得信赖的PHP框架'
                ]
            },
                        {
                'name': 'thinkphp',
                'path': 'public/',     # * 访问public路径时会提示相应信息
                'data': '',
                'fingerprint': [
                    r'十年磨一剑-为API开发设计的高性能框架',
                    r'十年磨一剑 - 为API开发设计的高性能框架',
                    r':\)',
                    r'ThinkPHP.*V.*',
                    r'\d{0,3}载初心不改 - 你值得信赖的PHP框架'
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
                    r'<title>YONYOU NC</title>',
                    r'//判断操作系统.*\.\./Client/Uclient/UClient\.dmg.*UClient客户端下载',
                    r'<title>用友GRP-U8.*行政事业内控管理软件.*</title>',
                    r'<div class="foot foot1".*>北京用友政务软件有限公司.*</div>',
                    r'<script type="text/javascript" src="/yyoa/seeyonoa/common/js/jquery/jquery\.js"></script>',
                    r'<script type="text/javascript" src="seeyonoa/common/js/popDialog\.jsp"></script>',
                    r'<li class="A6_name"><img src="seeyonoa/ui/images/login/oem_name\.png" /></li>',
                    r'<title>.* 《用友U8\+OA基础版》</title>',
                    r'<title>.* 《用友U8-OA企业版》</title>',
                    r'<li class="copyright"><span>©用友软件珠海研发基地</span></li>',
                    r'<title>.*-FE协作办公平台\d\.\d(\.\d)?</title>'
                ]
            },
            {
                'name': 'zabbix',
                'path': '',
                'data': '',
                'fingerprint': [
                    r'<meta name="Author" content="Zabbix SIA" />',
                    r'<a target="_blank" class="grey link-alt" href="https?://www\.zabbix\.com.{0,30}Help',
                    r'class="grey link-alt" href="https?://www\.zabbix\.com/support\.php">Support',
                    r'href="https?://www\.zabbix\.com/">Zabbix SIA</a>'
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