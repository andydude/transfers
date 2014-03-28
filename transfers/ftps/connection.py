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
transfers.ftps.connection
"""


import ftplib
import socket
import ssl

from .settings import DEFAULT_PORT, DEFAULT_BINARY, DEFAULT_PASSIVE, DEFAULT_SECURE, DEFAULT_AUTHTYPE
from ..ftp.connection import FTPTransfersMixin

class FTPSTransfersMixin(FTPTransfersMixin):

    def auth_type_from_ssl_version(self, v):
        if v == ssl.PROTOCOL_TLSv1:
            return 'TLS'
        return 'SSL'
    
    def auth(self, authType=DEFAULT_AUTHTYPE, secure=DEFAULT_SECURE):
        '''Set up secure control connection by using TLS/SSL.'''
        if isinstance(self.sock, ssl.SSLSocket):
            raise ValueError("Already using TLS")
        
        if authType is None:
            if self.ssl_version == ssl.PROTOCOL_TLSv1:
                authType = 'TLS'
            else:
                authType = 'SSL'
        if authType != self.authType:
            resp = self._request('AUTH', authType)
        if secure:
            self.sock = self._wrap_control_socket(self.sock)
            self.file = self.sock.makefile(mode='rb')
            
        return resp

    def login(self, user='', passwd='', acct='', secure=DEFAULT_SECURE, authType=DEFAULT_AUTHTYPE):
        if secure and not isinstance(self.sock, ssl.SSLSocket):
            self.auth(secure, authType)
        return FTPTransfersMixin.login(self, user, passwd, acct)

    def prot_p(self):
        '''Set up secure data connection.'''
        _    = self._request('PBSZ', '0')
        resp = self._request('PROT', 'P')
        self._prot_p = True
        return resp

    def prot_c(self):
        '''Set up clear text data connection.'''
        resp = self._request('PROT', 'C')
        self._prot_p = False
        return resp

    # a IConnectHook
    def _wrap_control_socket(self, conn):
        return self._wrap_socket(conn)

    # a IConnectHook
    def _wrap_socket(self, conn):
        if self._prot_p:
            conn = ssl.wrap_socket(conn, self.keyfile, self.certfile,
                                   ssl_version=self.ssl_version)
        return conn

    # a IConnectHook
    def _unwrap_socket(self, conn):
        if isinstance(conn, ssl.SSLSocket):
            conn.unwrap()
        return conn

    # overriddent methods

    def _makeconnection(self, method, *args, **kwargs):
        kwargs.setdefault('connCallback', self._wrap_socket)
        return FTPTransfersMixin._makeconnection(self, method, *args, **kwargs)

    def retr(self, self, method, *args, **kwargs):
        kwargs.setdefault('connCallback', self._unwrap_socket)
        return FTPTransfersMixin.retr(self, method, *args, **kwargs)
        
    def stor(self, method, *args, **kwargs):
        kwargs.setdefault('connCallback', self._unwrap_socket)
        return FTPTransfersMixin.stor(self, method, *args, **kwargs)

#     def retrbinary(self, cmd, callback, blocksize=8192, rest=None):
#         pass
# 
#     def retrlines(self, cmd, callback = None):
#         pass
# 
#     def storbinary(self, cmd, fp, blocksize=8192, callback=None, rest=None):
#         pass
#     
#     def storlines(self, cmd, fp, callback=None):
#         pass
    

class FTPSConnection(ftplib.FTP_TLS, FTPSTransfersMixin):
    scheme = 'ftps'
    host = ''
    port = DEFAULT_PORT
    bufferSize = 8192
    repType = "ascii"
    authType = ''
    protection = "clear" # or "private"
    timeout = socket._GLOBAL_DEFAULT_TIMEOUT
    passive = DEFAULT_PASSIVE
    binary = DEFAULT_BINARY
    history = []
    ssl_version = ssl.PROTOCOL_TLSv1

    auth = FTPSTransfersMixin.auth
    abort = FTPSTransfersMixin.abort
    login = FTPSTransfersMixin.login
    rename = FTPSTransfersMixin.rename
    connect = FTPSTransfersMixin.connect
    prot_p = FTPSTransfersMixin.prot_p
    prot_c = FTPSTransfersMixin.prot_c

    #def __init__(self, host='', user='', passwd='', acct='', keyfile=None, certfile=None, timeout=_GLOBAL_DEFAULT_TIMEOUT):
