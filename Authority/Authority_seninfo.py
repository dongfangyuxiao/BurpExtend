#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/12/13 10:46
# @Author  : xiaodong
# @github  : https://github.com/dongfangyuxiao/
# @Site    : #
# @File    : Authority_1.py
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
from java.net import URL
from urlparse import urlparse  #我自己的环境是py3，但bp只支持py2，这里没有导入没关系的
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
sys.path.append('C:/Python27/Lib/site-packages')
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # 屏蔽ssl警告
class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.registerScannerCheck(self)  # 注册扫描插件
        self._callbacks.setExtensionName("Authority")  # 定义插件的名称
        print("for Authority Test")
        self.proxies = {
            'http': 'http://127.0.0.1:9090',
            'https': 'https://127.0.0.1:9090',
        }



    def doPassiveScan(self, baseRequestResponse):
        Request = baseRequestResponse.getRequest()
        Response = baseRequestResponse.getResponse()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(Request)
        ResHeaders, ResBodys, ResStatusCode, resLength = self.get_response_info(Response)
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps, = self.get_server_info(httpService)

        heaers = {
        }


        if (1==1):
            newReqUrl = self.get_request_url(protocol, reqHeaders,host,port)
            blackFile = ['.js','.css','.jpg','.png','.gif','v=1.0','.ico','woff2','timestamp','.ttf','.jpeg','woff','img']
            #print newReqUrl
            newHeaders = reqHeaders[2:]

            for header in newHeaders:
                if ('Authorization' not in header)  and ('token' not in header) and  ('Cookie' not  in header):
                    heaers[header.split(':')[0]] = "".join(header.split(':')[1:]).replace(" ","")
            heaedersParaller = heaers.copy()

            heaedersParaller['Cookie'] = 'Hm_lvt_abc41f7b78200269311e638009920af4=1585406136; Hm_lpvt_abc41f7b78200269311e638009920af4=1585406136; Corp_ResLang=zh-cn; zz_plt_biz_abt_home=B; zz_plt_biz_abt_register=E; _bfi=p1%3D10650033730%26p2%3D10650033730%26v1%3D4%26v2%3D3; login_uid=2DAE2FF415280CF18E291F4D2C022C51; login_type=0; cticket=D6289E7BEEFE60F70ED3ECCE389692173CD9864ED5495E8952BAB5AE9AB8AA64; AHeadUserInfo=VipGrade=0&VipGradeName=%C6%D5%CD%A8%BB%E1%D4%B1&UserName=%D2%D1%D5%F4%B7%A2&NoReadMessageCount=1; ticket_ctrip=bJ9RlCHVwlu1ZjyusRi+ypZ7X2r4+yojeV9JiOu4A66roZwRMZPTDO4AwNOkUccixAPhRxhhOv3Pxvb989z5O6uIH3Ny/HMk2Vok2hbQmCNmSgPYSckYVOzdRYczngsZrbo1yO2Q34eTjN0eCimuY/2mCjKAE/0EIt4mgcMl41loZqoMZyCKmCq9DpmcatV3IfpCT2mv8iAYT8NkbpwnV+Re/OwR5n0/fEq7mxcmdBA9lrAqL0U45/eg/zvIuF79RH9/KR6gHJac53GNR0UTa0l7TYElpD+of/ieyOJ+ax8=; DUID=u=2DAE2FF415280CF18E291F4D2C022C51&v=0; IsNonUser=u=2DAE2FF415280CF18E291F4D2C022C51&v=0; _bfa=1.1585406148670.3nvpaa.1.1585406148670.1585406148670.1.5; _bfs=1.5'
            if str(newReqUrl).endswith(tuple(blackFile)) or ('js?'in newReqUrl) or ('image' in newReqUrl):
                pass
            else:
                self.unauthority(reqMethod, newReqUrl, heaers, reqBodys,resLength)
                self.parallelTest(reqMethod, newReqUrl, heaedersParaller, reqBodys,resLength)
                #link = reqHeaders[0].split(' ')[1]
                self.sensitiveInfo(newReqUrl,reqHeaders,reqBodys,ResBodys)










    def consolidateDuplicateIssues(self, existingIssue, newIssue):

        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # report the issue
        return None



    def unauthority(self,reqMethod,newReqUrl,heaers,ResBodys,resLength):
        try:
            if reqMethod == "GET":
                response = requests.get( newReqUrl, headers=heaers,
                                            verify=False, allow_redirects=True, timeout=5)

            else:

                response = requests.request(reqMethod,newReqUrl, headers=heaers,  data=ResBodys,
                                     verify=False, allow_redirects=True, timeout=5)
            responseContent = response.content
        except Exception as e:
            print e
            responseContent = ""
            pass

        if len(responseContent)==resLength:
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[MayBe unauthority]', newReqUrl, heaers,
                                                                           ResBodys)
            print content
            self.save(content)



    def parallelTest(self,reqMethod,newReqUrl,heaers,ResBodys,resLength):

        try:
            if reqMethod == "GET":
                response = requests.get( newReqUrl, headers=heaers,
                                            verify=False, allow_redirects=True, timeout=5)

            else:

                response = requests.request(reqMethod,newReqUrl, headers=heaers,  data=ResBodys,
                                     verify=False, allow_redirects=True, timeout=5)
            responseContent = response.content
        except Exception as e:
            print e
            responseContent = ""
            pass

        if len(responseContent)==resLength:
            content = '[+]{} -> {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[MayBe Parallel Find]', newReqUrl, heaers,
                                                                           ResBodys)
            print content
            self.save(content)


    def sensitiveInfo(self,newReqUrl,newReqHeaders,reqBodys,ResBodys):
        #print link
        #[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|1\d{10}|[3-6]\d{14,19}|
        infoFlag = re.compile(r'.*(手机号|身份证号|用户id|银行卡号|用户名).*')#
        cerFlag = re.compile('(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5])\d{4}(?:1[89]|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?:\d|[xX]|)')
        cert15 = re.compile('(?:1[1-5]|2[1-3]|3[1-7]|4[1-6]|5[0-4]|6[1-5])\d{4}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}')#这是身份证15位
        #print (reqBodys+ResBodys).decode("utf-8").lower()

        errorInject = infoFlag.findall((reqBodys+ResBodys).lower().strip())


        if errorInject:
            #

            content = '[+]{} ->{} {}\n[Headers] -> {}\n[Bodys] -> {}'.format('[Sentive Info GET]', errorInject, newReqUrl,
                                                                             newReqHeaders, reqBodys)
            print (content)
            self.save(content + '\t\n')
            print ('-' * 50)









    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps



    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)
        resHeaders = analyzedResponse.getHeaders()
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()
        resStatusCode = analyzedResponse.getStatusCode()

        resLength = len(resBodys)
        return resHeaders, resBodys, resStatusCode, resLength

    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType



    def get_request_url(self, protocol, reqHeaders, host, port):
        link = reqHeaders[0].split(' ')[1]

        if link.startswith('http'):
            return link
        else:
            return protocol + '://' + host + ":" + str(port) + link



    def save(self, content):
        #print(content)
        f = open('burp_Authority.txt', 'a+')
        f.writelines(content + '\n\n')
        f.close()

    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)
        reqHeaders = analyzedRequest.getHeaders()
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()
        reqMethod = analyzedRequest.getMethod()
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters

