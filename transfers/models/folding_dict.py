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

import six
import collections

class FoldingDict(collections.MutableMapping):
    '''For compatibility with requests.structures.CaseInsensitiveDict'''
    
    PairCls = collections.namedtuple('Pair', 'key value')
    
    def __init__(self, data=None, **kwargs):
        self._store = dict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __eq__(self, other):
        if not isinstance(other, collections.Mapping):
            return NotImplemented
        
        other = FoldingDict(other)
        return dict(self.lower_items()) == dict(other.lower_items())
        
    def __getitem__(self, key):
        return self._store[key.lower()].value

    def __iter__(self):
        return (givenkey for givenkey, _ in self._store.values())

    def __len__(self):
        return len(self._store)
    
    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, dict(self.items()))

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = self.PairCls(key, value)

    # Copy is required
    def copy(self):
        return FoldingDict(self._store.values())

    def given_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((keyval.key, keyval.value) for keyval in self._store.values())

    # For compatibility with requests.structures.CaseInsensitiveDict
    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval.value) for (lowerkey, keyval) in self._store.items())

    def upper_items(self):
        """Like iteritems(), but with all uppercase keys."""
        return ((lowerkey.upper(), keyval.value) for (lowerkey, keyval) in self._store.items())

    def title_items(self):
        """Like iteritems(), but with all titlecase keys."""
        return ((lowerkey.title(), keyval.value) for (lowerkey, keyval) in self._store.items())

class HTTPHeaderDict(FoldingDict):
    '''For compatibility with urllib3._collections.HTTPHeaderDict'''

    sep = ', '

    def add(self, key, value):
        orig_value = self._store.get(key.lower())
        if orig_value and isinstance(orig_value, six.string_types) and \
                          isinstance(value, six.string_types):
            value = orig_value + self.sep + value
        self[key] = value

    def getlist(self, key):
        return self[key].split(', ') if key in self else []

