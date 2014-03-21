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
    """The built-in HTTP Adapter for urllib3.

    Provides a general-case interface for Requests sessions to contact HTTP and
    HTTPS urls by implementing the Transport Adapter interface. This class will
    usually be created by the :class:`Session <Session>` class under the
    covers.

    :param pool_connections: The number of urllib3 connection pools to cache.
    :param pool_maxsize: The maximum number of connections to save in the pool.
    :param int max_retries: The maximum number of retries each connection
        should attempt. Note, this applies only to failed connections and
        timeouts, never to requests where the server returns a response.
    :param pool_block: Whether the connection pool should block for connections.

    Usage::

      >>> import requests
      >>> s = requests.Session()
      >>> a = requests.adapters.HTTPAdapter(max_retries=3)
      >>> s.mount('http://', a)
    """
    __attrs__ = ['max_retries', 'config', '_pool_connections', '_pool_maxsize',
                 '_pool_block']

    def __init__(self, max_retries=DEFAULT_RETRIES):
        self.max_retries = max_retries
        super(FTPAdapter, self).__init__()

    def close(self):
        """Disposes of any internal state.
        """
        pass

    def get_connection(self, url, auth=None, proxies=None):
        parsedUrl = parse_url(url)
        
        if parsedUrl.scheme == "ftp":
            ConnectionCls = FTPConnection
        elif parsedUrl.scheme == "ftps":
            ConnectionCls = None
        elif parsedUrl.scheme == "sftp":
            ConnectionCls = None
        elif parsedUrl.scheme == "file":
            ConnectionCls = None

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

#         if stream:
#             timeout = TimeoutSauce(connect=timeout)
#         else:
#             timeout = TimeoutSauce(connect=timeout, read=timeout)
        #TODO, cwd(parsedUrl.path)
        try:
            r = conn.request(request.method, *request.args)
        except socket.error as sockerr:
            raise ConnectionError(sockerr, request=request)
#         except MaxRetryError as e:
#             raise ConnectionError(e, request=request)
# 
#         except _ProxyError as e:
#             raise ProxyError(e)
# 
#         except (_SSLError, _HTTPError) as e:
#             if isinstance(e, _SSLError):
#                 raise SSLError(e, request=request)
#             elif isinstance(e, TimeoutError):
#                 raise Timeout(e, request=request)
#             else:
#                 raise

        if not stream:
            r.content

        return r
