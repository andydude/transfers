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

DEFAULT_RETRIES = 0
DEFAULT_PORT = 21
DEFAULT_BINARY = None
DEFAULT_PASSIVE = True
DEFAULT_NEWLINE = "\r\n"

DEFAULT_RESPONSES = {
    110: 'Restart marker replay.',
    120: 'Service ready in nnn minutes.',
    211: 'System status.',
    212: 'Directory status.',
    213: 'File status.',
    214: 'Help message.',
    215: 'NAME system type.',
    220: 'Service ready for new user.',
    221: 'Service closing control connection.',
    225: 'Data connection open; no transfer in progress.',
    257: '"PATHNAME" created.',
    331: 'User name okay, need password.',
    332: 'Need account for login.',
}
