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
transfers.sftp.settings
"""

DEFAULT_PATH = "/"
DEFAULT_SYMBOLIC = True
DEFAULT_FOLLOW = True

import paramiko

FTP_TO_SFTP_CODE = {
    'INIT':         paramiko.sftp.CMD_INIT,
    'VERS':         paramiko.sftp.CMD_VERSION,
    'OPEN':         paramiko.sftp.CMD_OPEN,
    'CLOSE':        paramiko.sftp.CMD_CLOSE,
    'READ':         paramiko.sftp.CMD_READ,
    'WRITE':        paramiko.sftp.CMD_WRITE,
    'LSTAT':        paramiko.sftp.CMD_LSTAT,
    'FSTAT':        paramiko.sftp.CMD_FSTAT,
    '__SETSTAT':    paramiko.sftp.CMD_SETSTAT,
    '__FSETSTAT':   paramiko.sftp.CMD_FSETSTAT,
    '__OPENDIR':    paramiko.sftp.CMD_OPENDIR,
    '__READDIR':    paramiko.sftp.CMD_READDIR,
    'DELE':         paramiko.sftp.CMD_REMOVE,
    'MKD':          paramiko.sftp.CMD_MKDIR,
    'RMD':          paramiko.sftp.CMD_RMDIR,
    '__REALPATH':   paramiko.sftp.CMD_REALPATH,
    'STAT':         paramiko.sftp.CMD_STAT,
    '__RENAME':     paramiko.sftp.CMD_RENAME,
    '__READLINK':   paramiko.sftp.CMD_READLINK,
    '__SYMLINK':    paramiko.sftp.CMD_SYMLINK,
    '__STATUS':     paramiko.sftp.CMD_STATUS,
    '__HANDLE':     paramiko.sftp.CMD_HANDLE,
    'DATA':         paramiko.sftp.CMD_DATA,
    'NAME':         paramiko.sftp.CMD_NAME,
    'ATTRS':        paramiko.sftp.CMD_ATTRS,
}

FTP_TO_SFTP_NAME = {
    'CWD':          'chdir',
    'PWD':          'getcwd',
    'STOR':         'putfo', # also put
    'RETR':         'getfo', # also get
    'LSTAT':        'lstat',
    'FSTAT':        'fstat',
    'CHMOD':        'chmod',
    'CHOWN':        'chown',
    'UTIME':        'utime',
    '__TRUNCATE':   'truncate',
    'LIST':         'listdir_attr',
    'NLST':         'listdir',
    'DELE':         'remove',
    'MKD':          'mkdir',
    'RMD':          'rmdir',
    '__REALPATH':   'normalize',
    'STAT':         'stat',
    '__RENAME':     'rename',
    '__READLINK':   'readlink',
    '__SYMLINK':    'symlink',
}


# LIST:
#     __OPENDIR
#     __READDIR
#     __CLOSE


