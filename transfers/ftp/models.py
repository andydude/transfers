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
transfers.ftp.models
"""
import ftplib
import requests
import socket

from .settings import DEFAULT_BINARY, DEFAULT_PASSIVE, DEFAULT_NEWLINE, DEFAULT_RESPONSES
from .exceptions import FTPError

class FTPMessage(object):
    status = 200
    reason = "OK"
    body = None
    
    def __init__(self, obj):
        if isinstance(obj, basestring):
            self.from_string(obj)
        elif isinstance(obj, socket._fileobject):
            self.from_socketfileobject(obj)
        elif isinstance(obj, socket.SocketType):
            self.from_socket(obj)

    def __str__(self):
        if self.body:
            firstline = "%(status)d-%(firstline)s" % vars(self)
            lastline = "%(status)d %(lastline)s" % vars(self)
            lines = DEFAULT_NEWLINE.join([firstline] + self.body + [lastline])
        else:
            lines = "%(status)d %(firstline)s" % vars(self)
        return lines
    
    def from_string(self, resp):
        lines = resp.split(DEFAULT_NEWLINE)
        line = lines[0]
        if line[3:4] == '-':
            _, self.firstline = lines[0].split('-', 1)
            self.body = DEFAULT_NEWLINE.join(lines[1:-1])
            self.status, self.lastline = lines[-1].split(' ', 1)
        else:
            self.status, self.firstline = line.split(' ', 1)
            self.lastline = self.firstline
        self.status = int(self.status)
        self.reason = DEFAULT_RESPONSES.get(self.status)

    def from_socket(self, sock):
        sockfile = sock.makefile('rb')
        self.from_socketfileobject(sockfile)
        
    # ftplib.FTP.getmultiline
    def from_socketfileobject(self, sockfile):
        line = FTPMessage.readline_from_socket(sockfile)
        if line[3:4] == '-':
            self.body = ''
            status, self.firstline = line.split('-', 1)
            while True:
                nextline = FTPMessage.readline_from_socket(sockfile)
                if nextline[:3] == status and nextline[3:4] != '-':
                    break
                else:
                    self.body += nextline + DEFAULT_NEWLINE
            self.status, self.lastline = nextline.split(' ', 1)
        else:
            self.status, self.firstline = line.split(' ', 1)
            self.lastline = self.firstline
        self.status = int(self.status)
        self.reason = DEFAULT_RESPONSES.get(self.status)

    # ftplib.FTP.getline
    @staticmethod
    def readline_from_socket(sockfile):
        line = sockfile.readline()
        if not line: raise EOFError
        if line[-2:] == DEFAULT_NEWLINE: 
            line = line[:-2]
        elif line[-1:] in DEFAULT_NEWLINE:
            line = line[:-1]
        return line

class FTPRequest(requests.Request):
    def __init__(self, args = [], binary = DEFAULT_BINARY, passive = DEFAULT_PASSIVE,
                 repForm = "nonprint", repType = "ascii", repByteSize = 8,
                 fileStructure = "file", transferMode = "stream", **kwargs):
        super(FTPRequest, self).__init__(**kwargs)
        
        del self.headers
        del self.cookies
        
        self.args = args
        self.binary = binary
        self.passive = passive
        self.repForm = repForm
        self.repType = repType
        self.repByteSize = repByteSize
        self.fileStructure = fileStructure
        self.transferMode = transferMode

class FTPResponse(requests.Response):

    def close(self):
        pass

    @property
    def ok(self):
        try:
            self.raise_for_status()
        except FTPError:
            return False
        return True

    @property
    def ok1(self):
        return 100 <= self.status_code < 200

    @property
    def ok2(self):
        return 200 <= self.status_code < 300

    @property
    def ok3(self):
        return 300 <= self.status_code < 400

    @property
    def path(self):
        return ftplib.parse257(self.raw)
    
    @property
    def size(self):
        s = self.raw.firstline
        try:
            return int(s)
        except (OverflowError, ValueError):
            return long(s)

    @property
    def time(self):
        s = self.raw.firstline
        try:
            return int(s)
        except (OverflowError, ValueError):
            return long(s)

    @property
    def lines(self):
        return self.text.split(DEFAULT_NEWLINE)
    
    def iter_content(self, size):
        return 0
    
    def raise_for_status(self):
        ftp_error_msg = ''

        if 400 <= self.status_code < 500:
            ftp_error_msg = '%s Transient Error: %s' % (self.status_code, self.reason)

        elif 500 <= self.status_code < 600:
            ftp_error_msg = '%s Permanent Error: %s' % (self.status_code, self.reason)

        if ftp_error_msg:
            raise FTPError(ftp_error_msg, response=self)
