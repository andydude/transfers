#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# transfers
# Copyright (c) 2014, Andrew Robbins, All rights reserved.
# 
# This library ("it") is free software; it is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; you can redistribute it and/or modify it under the terms of the
# GNU Lesser General Public License ("LGPLv3") <https://www.gnu.org/licenses/lgpl.html>.
from __future__ import absolute_import
"""
transfers.connection
"""

import ftplib
import io
import six
import socket

from .models import FTPMessage, FTPRequest, FTPResponse
from .settings import DEFAULT_PASSIVE, DEFAULT_PORT, DEFAULT_NEWLINE

class FTPConnection(object):
    scheme = 'ftp'
    host = ''
    port = DEFAULT_PORT
    bufferSize = 8192
    repType = "ascii"
    timeout = socket._GLOBAL_DEFAULT_TIMEOUT
    passive = DEFAULT_PASSIVE
    history = []

    # Initialization method (called by class instantiation).
    # Initialize host to localhost, port to standard ftp port
    # Optional arguments are host (for connect()),
    # and user, passwd, acct (for login())
    def __init__(self, host='', port='', user='', passwd='', acct='',
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        self.timeout = timeout
        if host:
            self.connect(host)
            if user:
                self.login(user, passwd, acct)
    
    def close(self):
        if self.file:
            self.file.close()
            self.sock.close()
            self.file = self.sock = None
            
    def connect(self, host='', port='', timeout=None):
        '''Connect to host.  Arguments are:
         - host: hostname to connect to (string, default previous host)
         - port: port to connect to (integer, default previous port)
        '''
        if host != '':
            self.host = host
        if port != '':
            self.port = port
        if timeout:
            self.timeout = timeout
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.file = self.sock.makefile('rb')
        self.welcome = self._getresponse()
        return self.welcome
    
    # ftplib.FTP.getresp
    # ftplib.FTP.voidresp
    def _getresponse(self, **kwargs):
        response = FTPResponse()
        response.raw = FTPMessage(self.file)
        response.status_code = response.raw.status
        response.reason = response.raw.reason
        if response.raw.body:
            response._content = response.raw.body
            response._content_consumed = True
        return response

    # ftplib.FTP.putline
    # ftplib.FTP.putcmd
    # ftplib.FTP.sendcmd
    # ftplib.FTP.voidcmd
    def _request(self, method, *args, **kwargs):
        line_parts = [method]
        line_parts.extend(args)
        line = ' '.join(map(str, line_parts))
        line += DEFAULT_NEWLINE
        self.sock.sendall(line)
        
        req = FTPRequest(method, **kwargs)
        req.method = method
        req.args = args
        resp = self._getresponse()
        resp.request = req
        
        # TODO: only if debugging is True
        self.history.append(resp)
        
        return resp
    
    # ftplib.FTP.sendport
    # ftplib.FTP.sendeprt
    def _sendport(self, method, host, port, family):
        '''Send a PORT/EPRT command with the current host and the given port number.'''
        if method == "PORT":
            hbytes = host.split('.')
            pbytes = [repr(port//256), repr(port%256)]
            hostport = ','.join(hbytes + pbytes)
            return self._request(method, hostport)
        elif method == "EPRT":
            af = 0
            if family == socket.AF_INET:
                af = 1
            elif family == socket.AF_INET6:
                af = 2
            if af == 0:
                raise ftplib.error_proto, 'unsupported address family'
            fields = ['', repr(af), host, repr(port), '']
            hostport = '|'.join(fields)
            return self._request(method, hostport)
        raise "unsupported port command"

    def _makesocket(self, family):
        msg = "getaddrinfo returns an empty list"
        sock = None
        for res in socket.getaddrinfo(None, 0, family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, _, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                sock.bind(sa)
            except socket.error, msg:
                if sock:
                    sock.close()
                sock = None
                continue
            break
        if not sock:
            raise socket.error, msg
        return sock

    # ftplib.FTP.makeport
    def _makeport(self, family):
        '''Create a new socket and send a PORT/EPRT command for it.'''
        sock = self._makesocket(family)
        sock.listen(1)
        port = sock.getsockname()[1] # Get proper port
        host = self.sock.getsockname()[0] # Get proper host
        if family == socket.AF_INET:
            resp = self._sendport('PORT', host, port, family)
        else:
            resp = self._sendport('EPRT', host, port, family)
        return sock, resp

    # ftplib.FTP.makepasv
    def _makepasv(self, family):
        '''Create a new connection and send a PASV/EPSV command for it.'''
        if family == socket.AF_INET:
            resp = self._request('PASV')
            host, port = ftplib.parse227(str(resp.raw))
        else:
            resp = self._request('EPSV')
            host, port = ftplib.parse229(str(resp.raw), self.sock.getpeername())
        conn = socket.create_connection((host, port), self.timeout)
        return conn, resp, host, port
    
    # ftplib.FTP.ntransfercmd
    # ftplib.FTP.transfercmd
    def _makeconnection(self, method, *args, **kwargs):
        """Returns a urllib3 connection for the given URL. This should not be
        called from user code, and is only exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param url: The URL to connect to.
        :param proxies: (optional) A Requests-style dictionary of proxies used on this request.
        """
        passive = kwargs.get("passive", DEFAULT_PASSIVE)
        restartMarker = kwargs.get("restartMarker")
        
        size = None
        sockaddr = None
        if not passive:
            sock, _ = self._makeport(self.sock.family)
        else:
            conn, _, _, _ = self._makepasv(self.sock.family)
        if restartMarker is not None:
            self._request("REST", restartMarker)
        resp = self._request(method, *args, **kwargs)

        # Some servers apparently send a 200 reply to
        # a LIST or STOR command, before the 150 reply
        # (and way before the 226 reply). This seems to
        # be in violation of the protocol (which only allows
        # 1xx or error messages for LIST), so we just discard
        # this response.
#         if resp.raw[0] == '2':
#             resp = self._getresponse()
#         if resp.raw[0] != '1':
#             raise ftplib.error_reply, resp
        if not passive:
            conn, sockaddr = sock.accept()
        if resp.status_code == 150:
            # this is conditional in case we received a 125
            size = ftplib.parse150(str(resp.raw))
        return conn, size, sockaddr
    
    # ftplib.FTP.retrbinary
    # ftplib.FTP.retrlines
    def retr(self, method, *args, **kwargs):
        callback = kwargs.get("callback")
        isBinary = kwargs.get("binary")
        if isBinary is None:
            isBinary = kwargs.get("repType", "ascii")[0].upper() == "I"
        
        content = ""
        conn, _, _ = self._makeconnection(method, *args, **kwargs)
        data = conn.makefile('rb')
        while True:
            if isBinary:
                buf = data.read(self.bufferSize)
            else:
                buf = data.readline()
            if not buf:
                break
            content += buf
            if not isBinary:
                if buf[-2:] == DEFAULT_NEWLINE:
                    buf = buf[:-2]
                elif buf[-1:] == '\n':
                    buf = buf[:-1]
            if callback:
                callback(buf)
        data.close()
        conn.close()
        resp = self._getresponse(void=True)
        resp._content_consumed = True
        resp._content = content
        return resp
    
    # ftplib.FTP.storbinary
    # ftplib.FTP.storlines
    def stor(self, method, *args, **kwargs):
        callback = kwargs.get("callback")
        isBinary = kwargs.get("binary")
        if isBinary is None:
            isBinary = kwargs.get("repType", "ascii")[0].upper() == "I"
        
        data = kwargs.get('data')
        if isinstance(data, six.text_type):
            data = io.StringIO(data)
        if isinstance(data, six.binary_type):
            data = io.BytesIO(data)

        conn, _, _ = self._makeconnection(method, *args, **kwargs)
        while True:
            if isBinary:
                buf = data.read(self.bufferSize)
            else:
                buf = data.readline()
            if not buf: break
            if not isBinary and buf[-2:] != DEFAULT_NEWLINE:
                if buf[-1] in DEFAULT_NEWLINE: buf = buf[:-1]
                buf = buf + DEFAULT_NEWLINE
            conn.sendall(buf)
            if callback:
                callback(buf)
        conn.close()
        return self._getresponse(void=True)

    # kwargs = files=None, data=None, auth=None, hooks=None, 
    def request(self, method, *args, **kwargs):
        if method == "__LOGIN":
            resp = self.login(*args, **kwargs)
            return resp
        elif method == "__RENAME":
            resp = self.rename(*args, **kwargs)
            return resp
        elif method == "CWD":
            if len(args) and args[0] == '..':
                resp = self._request('CDUP', void=True)
            else:
                resp = self._request('CWD', *args, **kwargs)
            return resp
        elif method == "SIZE":
            repType = kwargs.get("repType", "image")[0].upper()
            resp = self._request("TYPE", repType)
            resp = self._request("SIZE", *args, **kwargs)
            return resp
        elif method == "STAT":
            repType = kwargs.get("repType", "ascii")[0].upper()
            resp = self._request("TYPE", repType)
            resp = self._request("STAT", *args, **kwargs)
            return resp
        elif method in ["RETR"]:
            repType = kwargs.get("repType", "ascii")[0].upper()
            resp = self._request("TYPE", repType)
            resp = self.retr(method, *args, **kwargs)
            return resp
        elif method in ["STOR", "STOU", "APPE"]:
            repType = kwargs.get("repType", "ascii")[0].upper()
            resp = self._request("TYPE", repType)
            resp = self.stor(method, *args, **kwargs)
            return resp
        elif method in ["LIST", "NLST", "MLSD"]:
            repType = kwargs.get("repType", "ascii")[0].upper()
            resp = self._request("TYPE", repType)
            resp = self.retr(method, *args, **kwargs)
            return resp
        else:
            resp = self._request(method, *args, **kwargs)
            return resp
    
    def login(self, username='', password='', account=''):
        '''Login, default anonymous.'''
        if not username: username = 'anonymous'
        if not password: password = ''
        if not account: account = ''
        if username == 'anonymous' and password in ('', '-'):
            password = password + 'anonymous@'
        resp = self._request('USER', username)
        if resp.ok_intermediate:
            resp = self._request('PASS', password)
        if resp.ok_intermediate:
            resp = self._request('ACCT', account)
        return resp

    def rename(self, path='', destpath=''):
        resp = self.request("RNFR", path)
        resp = self.request("RNTO", destpath)
        return resp
