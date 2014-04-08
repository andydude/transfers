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
transfers.sftp.connection
"""

import socket
import paramiko

from .settings import FTP_TO_SFTP_NAME

class SFTPConnection(object):
    """
    transfers.sftp.connection.SFTPConnection

    This represents the primary control socket over which most commands are sent.

    It has the following constants:
      - scheme (constant for each connection class)

    It has the following state:
      - current auth (username, password, account)
      - current host (hostname, ipaddress, port)
      - current path (expected output of the PWD command)
      - current passive (whether to use PORT or PASV)
      - current binary (simplification of repType)
      - current follow (whether to follow symbolic links)
      - current timeout (may include connect, send, wait, receive timeouts)
      - current bufferSize (may include ssl, send, receive buffer sizes)

    It has the following legacy state:
      - current authType (the first argument to the AUTH command)
      - current repType (the first argument to the TYPE command)
      - current repForm (the second argument to the TYPE A command)
      - current repByteSize (the second argument to the TYPE L command)
      - current fileStructure (argument to the STRU command)
      - current transferMode (argument to the MODE command)
      - current restartMark (argument to the REST command)
      - current welcome (readonly, response immediately after connect)
      - current systemType (readonly, response of SYST command)
      - current fileGlob (metacharacter expansion of local file names)
      - current preserve (modification time of retrieved files)
      - current allocate (whether to use ALLO command)
      - current unique (whether to use STOU command)
      - current append (whether to use APPE command)
    """

    def connect(self, host='', port='', timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        self._paramiko_transport = paramiko.Transport((host, port))
        
    def login(self, username='', password='', account=''):
        self._paramiko_transport.connect(username = username, password = password)
        self._paramiko_chan = self.makechan(self._paramiko_transport)
        self._paramiko_client = paramiko.SFTPClient(self._paramiko_chan)

    #paramiko.SFTPClient.from_transport(self._paramiko_transport)
    def makechan(self, t):
        chan = t.open_session()
        if chan: chan.invoke_subsystem('sftp')
        return chan
    
    def _request(self, method, *args, **kwargs):
        attr = FTP_TO_SFTP_NAME.get(method)
        if not attr: return None
        func = getattr(self._paramiko_client, attr)
        if not func: return None
        return func(*args, **kwargs)

