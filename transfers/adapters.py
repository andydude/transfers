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
transfers.adapters
"""

import socket

from requests.adapters import BaseAdapter
from requests.exceptions import ConnectionError
from requests.packages.urllib3.util import parse_url

from .ftp.settings import DEFAULT_RETRIES
from .ftp.connection import FTPConnection

class FTPAdapter(BaseAdapter):
    """The built-in FTP Adapter.

    Provides a general-case interface for Transfers sessions to contact FTP and
    FTPS urls by implementing the Transport Adapter interface.

    :param int max_retries: The maximum number of retries each connection
        should attempt. Note, this applies only to failed connections and
        timeouts, never to requests where the server returns a response.

    Usage::

      >>> import requests
      >>> import transfers
      >>> s = requests.Session()
      >>> a = transfers.adapters.FTPAdapter(max_retries=3)
      >>> s.mount('ftp://', a)
    """
    __attrs__ = ['max_retries', 'config']

    def __init__(self, max_retries=DEFAULT_RETRIES, conn_cls=None):
        self.conn_cls = conn_cls
        self.max_retries = max_retries
        super(FTPAdapter, self).__init__()

    def close(self):
        """Disposes of any internal state.
        """
        pass

    def get_connection_class(self, scheme, auth=None, proxies=None):
        ConnectionCls = None
        if self.conn_cls:
            ConnectionCls = self.conn_cls
        elif scheme == "ftp":
            ConnectionCls = FTPConnection
        elif scheme == "ftps":
            from .ftps.connection import FTPSConnection
            ConnectionCls = FTPSConnection
        elif scheme == "sftp":
            from .sftp.connection import SFTPConnection
            ConnectionCls = SFTPConnection
        elif scheme == "file":
            from .file.connection import FileConnection
            ConnectionCls = FileConnection
        return ConnectionCls
    
    def get_connection(self, url, auth=None, proxies=None):
        parsedUrl = parse_url(url)

        username = ''
        password = ''
        account = ''
        if not auth:
            auth = parsedUrl.auth
        if auth:
            username = auth[0]
            password = auth[1]
            if len(auth) == 3: 
                account = auth[2]
            
        ConnectionCls = self.get_connection_class(parsedUrl.scheme, auth, proxies)
        conn = ConnectionCls(host=parsedUrl.host,
                             port=parsedUrl.port,
                             user=username,
                             passwd=password,
                             acct=account)
        return conn
    
    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) The timeout on the request.
        :param verify: (optional) Whether to verify SSL certificates.
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        """

        conn = self.get_connection(request.url, auth=request.auth, proxies=proxies)
        #self.cert_verify(conn, request.url, verify, cert)
        #url = self.request_url(request, proxies)

        #TODO, cwd(parsedUrl.path)
        try:
            r = conn.request(request.method, *request.args)
        except socket.error as sockerr:
            raise ConnectionError(sockerr, request=request)

        if not stream:
            r.content

        return r
