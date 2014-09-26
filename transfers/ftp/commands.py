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
transfers.ftp.commands
"""

COMMAND_TO_METHOD = {

    # RFC 959 - deprecated FTP commands
    'MLFL': None,
    'MAIL': None,
    'MSND': None,
    'MSOM': None,
    'MSAM': None,
    'MRSQ': None,
    'MRCP': None,
    'XSEN': None, # RFC 737
    'XSEM': None, # RFC 737
    'XMAS': None, # RFC 737
    'XRSQ': None, # RFC 743
    'XRCP': None, # RFC 743
    'XMKD': None, # RFC 775
    'XRMD': None, # RFC 775
    'XPWD': None, # RFC 775
    'XCUP': None, # RFC 775

    # RFC 959 - FTP access control commands - login
    '__LOGIN': 'login', # same as USER, PASS, ACCT
    'USER': '_send_user',
    'PASS': '_send_pass',
    'ACCT': 'account',

    # RFC 959 - FTP access control commands - chdir
    '__CHDIR': 'chdir',     # same as CDUP or CWD
    'CDUP': '_send_cdup',
    'CWD': '_send_cwd',

    # RFC 959 - FTP access control commands
    'SMNT': '_send_smnt',
    'REIN': '_send_rein',
    'QUIT': '_send_quit', # bye close disconnect

    # RFC 959 - FTP transfer parameter commands
    '__MAKEPASV': 'makepasv',
    '__MAKEPORT': 'makeport',
    '__TRANSFER': 'transfer',
    'PORT': '_send_port',
    'PASV': '_send_pasv',
    'EPSV': '_send_epsv', # RFC 2428
    'EPRT': '_send_eprt', # RFC 2428
    'LPRT': '_send_lprt', # RFC 1639
    'LPSV': '_send_lpsv', # RFC 1639
    'STRU': '_send_stru',
    'TYPE': '_send_type',
    'MODE': '_send_mode',

    # RFC 959 - FTP service commands - get
    '__GET': 'get',
    'RETR': '_send_retr',

    # RFC 959 - FTP service commands - put
    '__PUT': 'put',
    'STOR': '_send_stor',
    'STOU': '_send_stou',
    'APPE': '_send_appe',
    'ALLO': '_send_allo',
    'REST': '_send_rest',

    # RFC 959 - FTP service commands - rename
    '__RENAME': 'rename', # (oldpath, newpath, flags?)
    'RNFR': '_send_rnfr',
    'RNTO': '_send_rnto',

    # RFC 959 - FTP service commands
    'ABOR': 'abort',
    'DELE': 'delete', # paramiko remove()
    'RMD': 'rmdir',
    'MKD': 'mkdir',
    'PWD': 'pwd',
    'LIST': 'lsdir', # ls, dir
    'NLST': 'names',
    'SITE': '_send_site',
    'SYST': '_send_syst',
    'STAT': 'stat', # paramiko.stat() # (path, flags?, follow?)
    'HELP': 'help',
    'NOOP': '_send_noop',
    
    # RFC 2228 commands
    'AUTH': '_send_auth',
    'ADAT': '_send_adat',
    'PROT': '_send_prot',
    'PBSZ': '_send_pbsz',
    'CCC': '_send_ccc',
    'MIC': '_send_mic',
    'CONF': '_send_conf',
    'ENC': '_send_enc',
    
    # RFC 2389 commands
    'FEAT': 'features',
    'OPTS': 'options',

    # RFC 2640 commands
    'LANG': '_send_lang',
    
    # RFC 3659 commands
    'SIZE': 'size',
    'MDTM': '_send_mdtm',
    'TVFS': '_send_tvfs',
    'MLST': '_send_mlst',
    'MLSD': '_send_mlsd',
    
    # Miscellaneous commands
    '__CHMOD': 'chmod', # in ftp, sftp
    '__CHOWN': 'chown',
    '__UTIME': 'utime',
    '__TRUNCATE': 'truncate',
    '__CONNECT': 'connect',

    # Setting commands
    '__PASSIVE': 'set_passive', # ftplib.FTP.set_pasv
    '__BINARY': 'set_binary', # same as "TYPE I" or "TYPE A"
    '__DEBUG': 'set_debuglevel',
    '__EPSV4': 'set_epsv4',

    # SFTP-only commands
    '__INIT': '_send_init',
    '__VERSION': '_send_version',
    '__LSTAT': '_send_lstat', # (path, flags?)
    '__SETSTAT': '_send_setstat', # (path, attrs)
    '__REALPATH': 'realpath', # paramiko normalize() # (oldpath, newpath, ctl?)
    '__READLINK': 'readlink', # (path)
    '__LINK': 'symlink', # paramiko symlink() # (newpath, oldpath, sym?)
    '__STATUS': '_send_status',
    '__HANDLE': '_send_handle',
    '__DATA': '_send_data',
    '__NAME': '_send_name',
    '__ATTRS': '_send_attrs',
    
    # SFTP-only handle commands
    '__OPEN': '_send_open', # (filename, access?, flags?, attrs?)
    '__CLOSE': '_send_close', # (handle)
    '__READ': '_send_read', # (handle, length, offset?)
    '__WRITE': '_send_write', # (handle, data, offset?)
    '__FSTAT': 'fstat', # (handle, flags?)
    '__FSETSTAT': '_send_fsetstat', # (handle, attrs)
    '__OPENDIR': '_send_opendir', # (handle)
    '__READDIR': '_send_readdir', # (handle)
    '__BLOCK': '_send_block', # (handle, length, offset?, mask?)
    '__UNBLOCK': '_send_unblock', # (handle, length, offset?)

}

METHOD_TO_COMMAND = {}
for command, method in METHOD_TO_COMMAND.items():
    METHOD_TO_COMMAND[method] = command
