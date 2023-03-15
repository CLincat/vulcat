#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from PluginManager import Vuln_Scan

class Scan(Vuln_Scan):
    def __init__(self):
        pass
    
    def POC(self, clients):
        pass
    
    def EXP(self, clients):
        pass

    def Start(self, clients):
        return self.POC(clients)
