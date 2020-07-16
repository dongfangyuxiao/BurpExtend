#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/10/25 15:25
# @Author  : xiaodong
# @github  : https://github.com/dongfangyuxiao/
# @Site    : #
# @File    : Burp_Dir.py
# @Software: PyCharm
#脚本就是把流量，纯净的，转发一份给awvs，有个问题啊，post型或其他的，awvs没有接口，比较尴尬
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
from java.net import URL
from urlparse import urlparse  #我自己的环境是py3，但bp只支持py2，这里没有导入没关系的
import sys
sys.path.append('C:/Python27/Lib/site-packages')
import requests
import json
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # 屏蔽ssl警告
class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.registerScannerCheck(self)  # 注册扫描插件
        self._callbacks.setExtensionName("awvs")  # 定义插件的名称
        print("for awvs scan")
        self.lfiD = []
        self.urls = []
        self.proxies = {
                'http': 'http://127.0.0.1:1080',
                'https': 'https://127.0.0.1:1080',
            }

        apikey = "1986ad8c0a5b3df4d7028d5f3c06e936c5db2384c91c9449e9ce5da2866c939ed"
        #apikey = "1986ad8c0a5b3df4d7028d5f3c06e936c0cec044fb3c540a1855732a825bb638b"
        self.awvsheaders = {"X-Auth": apikey, "content-type": "application/json"}
        self.awvsurl = "https://118.190.206.232:3443/"
        #self.awvsurl = "https://192.168.184.137:13443/"


    # 以上都是标准化程序

    def doPassiveScan(self, baseRequestResponse):
        Request = baseRequestResponse.getRequest()
        Response = baseRequestResponse.getResponse()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(Request)
        ResHeaders, ResBodys, ResStatusCode, resLength = self.get_response_info(Response)
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps, = self.get_server_info(httpService)

        heaers = {
        }
        awvsl = []
        newReqUrl = self.get_request_url(protocol, reqHeaders, host, port)
        #blackFile = ['js', 'css', 'jpg', 'png', 'gif', 'v=1.0', 'ico', 'woff2', 'timestamp', 'ttf','mp4','svg']
        #targetHost = ['saicmaxus', 'saicmotor', 'maxuscloud', 'rv2go', 'sxc','13', '226', '129', '130', '91', 'sxc', 'bihuo',
                     #'100', 'bihuoedu', 'islefoundation','anji-plus','anji-allways','anji-eql','anjiscf','ajhroro','196']
        #print newReqUrl

        #if str(newReqUrl).endswith(tuple(blackFile)):  # 多级或单级或类似baidu.net.cn的形势取主域名字段，比对是否在目标列表中
            #pass
        #else:

        print newReqUrl
        newHeaders2 = reqHeaders[2:]
        newHeaders = [str(i) for i in newHeaders2]  # 把列表转换为带'或"的，不然识别不出来
        tawvs = threading.Thread(target=self.startscan, args=(newReqUrl, newHeaders))
        tawvsxray = threading.Thread(target=self.startscanxray, args=(newReqUrl, newHeaders))
        tawvs.start()
        tawvsxray.start()



    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None

    def addtask(self,tarUrl):
        # 添加任务
        data = {"address": tarUrl, "description": "", "criticality": "10"}
        try:
            response = requests.post(self.awvsurl + "api/v1/targets", data=json.dumps(data), headers=self.awvsheaders, timeout=30,
                                     verify=False)
            result = json.loads(response.content)
            return result['target_id']
        except Exception as e:
            print(str(e))
            return
            pass

    def updateConfig(self,tarUrl,reqHeaders):
        target_id = self.addtask(tarUrl)
        url_update = self.awvsurl + "api/v1/targets/{0}/configuration".format(target_id)
        data = {
            "issue_tracker_id":"",
            "technologies":[],
            "custom_headers":reqHeaders,
            "custom_cookies":[],
            "debug":"false",
            "excluded_hours_id":""}
        try:
            response = requests.patch(url_update, data=json.dumps(data), headers=self.awvsheaders, timeout=30, verify=False
                                )
            return target_id
        except Exception as e:
            print e
            pass

    def updateConfigxray(self,tarUrl,reqHeaders):#这个只做扫描，流量给xray
        target_id = self.addtask(tarUrl)
        url_update = self.awvsurl + "api/v1/targets/{0}/configuration".format(target_id)
        data = {
            "issue_tracker_id":"",
            "technologies":[],
            "custom_headers":reqHeaders,
            "proxy": {"enabled": "true", "protocol": "http", "address": "118.214.88.135", "port": 9093},
            "custom_cookies":[],
            "debug":"false",
            "excluded_hours_id":""}
        try:
            response = requests.patch(url_update, data=json.dumps(data), headers=self.awvsheaders, timeout=30, verify=False
                                )
            return target_id
        except Exception as e:
            print e
            pass


    def startscan(self,tarUrl,reqHeaders):
        # 先获取全部的任务.避免重复
        # 添加任务获取target_id
        # 开始扫描
        target_id = self.updateConfig(tarUrl,reqHeaders)

        if target_id:
            data = {"target_id": target_id, "profile_id": "11111111-1111-1111-1111-111111111112",
                "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
            try:
                response = requests.post(self.awvsurl + "api/v1/scans", data=json.dumps(data), headers=self.awvsheaders, timeout=30,
                                         verify=False)


            except Exception as e:
                print(str(e))
                pass
                return

    def startscanxray(self,tarUrl,reqHeaders):
        # 先获取全部的任务.避免重复
        # 添加任务获取target_id
        # 开始扫描
        target_id = self.updateConfigxray(tarUrl,reqHeaders)

        if target_id:
            data = {"target_id": target_id, "profile_id": "11111111-1111-1111-1111-111111111117",
                "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
            try:
                response = requests.post(self.awvsurl + "api/v1/scans", data=json.dumps(data), headers=self.awvsheaders, timeout=30,
                                         verify=False)


            except Exception as e:
                print(str(e))
                pass
                return






    # 获取响应的一些信息：响应头，响应内容，响应状态码


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

    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
        resHeaders = analyzedResponse.getHeaders()  # getHeaders方法用于获取响应中包含的HTTP标头。返回：响应中包含的HTTP标头。
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()  # getBodyOffset方法用于获取消息正文开始的响应中的偏移量。返回：消息正文开始的响应中的偏移量。response[analyzedResponse.getBodyOffset():]获取正文内容
        resStatusCode = analyzedResponse.getStatusCode()  # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        resLength = len(resBodys)
        return resHeaders, resBodys, resStatusCode, resLength

    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

        # 获取请求的url

    def get_request_url(self, protocol, reqHeaders,host,port):
        link = reqHeaders[0].split(' ')[1]
        #host = reqHeaders[1].split(' ')[1]#忽略了如果json类型中，列表一不是host的情况，改变为
        if link.startswith('http'):
            return link
        else:
            return protocol + '://' + host +":"+str(port)+ link

    # 保存结果
    def save(self, content):
        print(content)
        f = open('burp_lfi.txt', 'at')
        f.writelines(content + '\n\n')
        f.close()

    def saveUrl(self, content):
        print(content)
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
