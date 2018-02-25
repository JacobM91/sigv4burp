from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import ITab
from burp import IBurpExtenderCallbacks

from java.io import PrintWriter
from datetime import datetime
from javax import swing
from java import awt
import java.lang as lang
from java.awt import Color
from java.awt import Font

import sys, os, base64, datetime, hashlib, hmac
import signer
import copy
import urlparse
import json

#hack for windows and ubuntu
sys.path.insert(0, 'c:/work/')
import signer

HEADERS_TO_REMOVE = ["x-amz-date", "x-amz-security-token", "authorization", "accept"]

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, ITab):
    
    def	registerExtenderCallbacks(self, callbacks):
        
        self._callbacks = callbacks
        self._callbacks.setExtensionName("sigv4 extender")

        self._helpers = callbacks.getHelpers()
                
        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)
        
        # register ourselves as a Proxy listener
        #callbacks.registerProxyListener(self)
        
        # register ourselves as a Scanner listener
        # callbacks.registerScannerListener(self)
        
        # register ourselves as an extension state listener
        # callbacks.registerExtensionStateListener(self)

        self.initGui()
        self._callbacks.addSuiteTab(self)
        
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if messageIsRequest: 
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            if not 'magicleap' in requestInfo.getUrl().getHost():
                return

            request_parameters = self.getQueryString(requestInfo.getUrl().getQuery())
            body = self.getBody(requestInfo.getBodyOffset(), messageInfo.getRequest())
           
            signedHeaders = signer.sign_request(requestInfo.getMethod(), self.access_key, self.secret_key, self.session_token, requestInfo.getUrl().getPath(), self.scopeUrlField.getText(), request_parameters, body)
            signedHeaders = self.getHeaders(requestInfo.getHeaders(), signedHeaders)
            
            newMessage = self._helpers.buildHttpMessage(signedHeaders, body)
            #print self._helpers.bytesToString(newMessage)
            messageInfo.setRequest(newMessage)

        return

    def initGui(self):
        self.sigv4ConfigurationTab = swing.JPanel()
        layout = swing.GroupLayout(self.sigv4ConfigurationTab)
        self.sigv4ConfigurationTab.setLayout(layout)

        self.addDomainInfo = swing.JLabel("Domain to test:")
        self.addDomainInfo.setFont(Font("Tahoma", 1, 12))
        self.configurationLoadedInfo = swing.JLabel("")
        self.configurationLoadedInfo.setFont(Font("Tahoma", 1, 12))
        self.isJsonCheck = swing.JCheckBox("JSON")
        self.isJsonCheck.setFont(Font("Tahoma", 1, 12))
        self.parseCredsBtn = swing.JButton('Load configuration', actionPerformed=self.parseCreds)
        self.credsPanel = swing.JScrollPane()
        self.credsText = swing.JTextArea("Paste Creds Here.")
        self.credsText.setLineWrap(True)
        self.credsPanel.setViewportView(self.credsText)
        self.scopeUrlField = swing.JTextField("api.magicleap.io")

        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(15)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addComponent(self.isJsonCheck)
                    .addComponent(self.credsPanel, swing.GroupLayout.PREFERRED_SIZE, 525, swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(self.addDomainInfo)
                    .addComponent(self.scopeUrlField, swing.GroupLayout.PREFERRED_SIZE, 350, swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(self.parseCredsBtn))
                            .addComponent(self.configurationLoadedInfo)
                        .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED))
                    .addComponent(self.addDomainInfo))
                .addContainerGap(26, lang.Short.MAX_VALUE)))

        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(10)
                .addComponent(self.isJsonCheck)
                .addGap(10)
                .addComponent(self.credsPanel, swing.GroupLayout.PREFERRED_SIZE, 125, swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(10)
                        .addComponent(self.addDomainInfo)
                        .addGap(10)
                        .addComponent(self.scopeUrlField, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(10)
                                .addComponent(self.parseCredsBtn)
                                .addGap(10)
                                .addComponent(self.configurationLoadedInfo)
                                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                .addContainerGap(swing.GroupLayout.DEFAULT_SIZE, lang.Short.MAX_VALUE)))))))
        
        return 

    def getTabCaption(self):
        return "Sigv4"

    def getUiComponent(self):
        return self.sigv4ConfigurationTab
    
    def parseCreds(self, button):
        creds = self.credsText.getText()
        try:
            if self.isJsonCheck.isSelected():
                credsTokens = json.loads(creds)
                self.access_key = credsTokens['accessKeyId']
                self.secret_key = credsTokens['secretKey']
                self.session_token = credsTokens['sessionToken']
            else:
                credsTokens = {"credentials": dict(urlparse.parse_qsl(urlparse.urlparse(creds).fragment))}
                self.access_key = credsTokens['credentials']['accessKeyId']
                self.secret_key = credsTokens['credentials']['secretKey']
                self.session_token = credsTokens['credentials']['sessionToken']
        except Exception as e:
            self.configurationLoadedInfo.setText("Configuration loaded falied, please check errors on Extender tab!")
            print 'You creds are wrong or you try to load URL as json'
            return
    
        self.configurationLoadedInfo.setText("Configuration loaded successfully!")

    def getQueryString(self, request_parameters):
        if request_parameters:
            print 'Query string [' + request_parameters + ']'
        else:
            request_parameters = ''

        return request_parameters

    def getHeaders(self, originHeaders, signedHeaders):
        headersToChange = []
       
        for header in originHeaders:
            if not header.lower().split(':')[0] in HEADERS_TO_REMOVE:
                headersToChange.append(header)

        for (header_name, header_value) in signedHeaders['headers'].items():
            headersToChange.append('{}: {}'.format(header_name, header_value))

        print "--------------"
        print headersToChange
        return headersToChange

    def getBody(self, bodyOffset, totalReq):
        body = "".join(map(chr, (totalReq[bodyOffset:])))
        if body:
            print 'New body [' + body + ']'
        else:     
            body = ''
    
        return body

    #
    # implement IProxyListener
    #

    def processProxyMessage(self, messageIsRequest, message):

        # self._stdout.println(
        #         ("Proxy request to " if messageIsRequest else "Proxy response from ") +
        #         message.getMessageInfo().getHttpService().toString())
        return
