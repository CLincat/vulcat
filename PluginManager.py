#!/usr/bin/env python3
# -*- coding:utf-8 -*-

'''
代码来源: https://cloud.tencent.com/developer/article/1567791
经过一点小修改后, 可用于vulcat
'''

### 插件式框架
import os
import sys
from imp import find_module
from imp import load_module
from lib.tool import color

class PluginManager(type):
    #静态变量配置插件路径
    __PluginPath = './payloads/'

    #调用时将插件注册
    def __init__(self, name, bases, dict):
        if not hasattr(self,'AllPlugins'):
            self.__AllPlugins = {}
        else:
            self.RegisterAllPlugin(self)

    #设置插件路径
    @staticmethod
    def SetPluginPath(path):
        if os.path.isdir(path):
            PluginManager.__PluginPath = path
        else:
            print(color.red('The "{PATH}" is not a valid path!!!\n\nPlease check config.yaml'.format(PATH=path)))
            print(color.reset())
            os._exit(1)

    @staticmethod
    def Whitelist(list, moduleName):
        '''
            检查该模块是否在 提供的白名单中
                在   -> True
                不在 -> False
        '''
        if not list:            # * 如果白名单中没有元素, 说明未启用白名单功能, 默认True
            return True
        
        for l in list:
            if l in moduleName:
                return True

        return False

    #递归检测插件路径下的所有插件，并将它们存到内存中
    @staticmethod
    def LoadAllPlugin(vulns = []):
        pluginPath = PluginManager.__PluginPath
        
        if not os.path.isdir(pluginPath):
            raise EnvironmentError
            # raise EnvironmentError,'%s is not a directory' % pluginPath

        items = os.listdir(pluginPath)
        for item in items:
            if os.path.isdir(os.path.join(pluginPath, item)):
                PluginManager.__PluginPath = os.path.join(pluginPath, item)
                PluginManager.LoadAllPlugin(vulns)
            else:
                if not PluginManager.Whitelist(vulns, item):
                    continue        # * 如果该Payload不在vulns白名单中, 则跳过添加
                
                if item.endswith('.py') and item != '__init__.py':
                    moduleName = item[:-3]
                    
                    if moduleName not in sys.modules:
                        fileHandle, filePath, dect = find_module(moduleName, [pluginPath])
                    else:
                        continue

                    try:
                        moduleObj = load_module(moduleName, fileHandle, filePath, dect)
                    except Exception as e:
                        print(color.red('The POC "{NAME}" is Error!!!'.format(NAME=item)))
                        print(e)
                        print(color.reset())
                        os._exit(1)
                    finally:
                        if fileHandle : fileHandle.close()

    #返回所有的插件
    @property
    def AllPlugins(self):
        return self.__AllPlugins

    #注册插件
    def RegisterAllPlugin(self, aPlugin):
        pluginName = '.'.join([aPlugin.__module__,aPlugin.__name__])
        pluginObj = aPlugin()
        self.__AllPlugins[pluginName] = pluginObj

    #注销插件
    def UnregisterPlugin(self, pluginName):
        if pluginName in self.__AllPlugins:
            pluginObj = self.__AllPlugins[pluginName]
            del pluginObj

    #获取插件对象。
    def GetPluginObject(self, pluginName = None):
        if pluginName is None:
            return self.__AllPlugins.values()
        else:
            result = self.__AllPlugins[pluginName] if pluginName in self.__AllPlugins else None
            return result

    #根据插件名字，获取插件对象。（提供插件之间的通信）
    @staticmethod
    def GetPluginByName(pluginName):
        if pluginName is None:
            return None
        else:
            for SingleModel in __ALLMODEL__:
                plugin = SingleModel.GetPluginObject(pluginName)
                if plugin:
                    return plugin

# * 插件框架的接入点。便于管理各个插件。
# * 各个插件通过继承接入点类，利用Python中metaclass的优势，将插件注册。
# * 接入点中定义了各个插件模块必须要实现的接口。
class Vuln_Scan(object, metaclass=PluginManager):
    '''
        漏洞检测
    '''
    def POC(self):
        print ('Please write the POC() function')

    def EXP(self):
        print ('Please write the EXP() function')

    def Start(self):
        print ('Please write the Start() function')

class Model_Placeholder(object, metaclass=PluginManager):
    '''
        占位
    '''
    def ABCDEFGHIJKLMNOPQRSTUVWXYZ(self):
        print ('Please write the ABCDEFGHIJKLMNOPQRSTUVWXYZ() function')

__ALLMODEL__ = (Vuln_Scan, Model_Placeholder)