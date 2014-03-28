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

