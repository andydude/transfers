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
transfers.sessions
"""

import os
import requests
from datetime import datetime
from requests.hooks import dispatch_hook
from requests.sessions import merge_hooks, merge_setting

# DEFAULT_REDIRECT_LIMIT = 30

from .adapters import FTPAdapter

class FTPSession(requests.Session):
    """A Requests session.

    Provides cookie persistence, connection-pooling, and configuration.

    Basic Usage::

      >>> import requests
      >>> s = requests.Session()
      >>> s.get('http://httpbin.org/get')
      200
    """

    __attrs__ = [
        'adapters', 'trust_env', 'auth', 'hooks',
        'timeout', 'proxies', 'verify', 'cert']

    def __init__(self):

        #: A case-insensitive dictionary of headers to be sent on each
        #: :class:`Request <Request>` sent from this
        #: :class:`Session <Session>`.
        self.headers = requests.utils.default_headers()

        #: Default Authentication tuple or object to attach to
        #: :class:`Request <Request>`.
        self.auth = None

        #: Dictionary mapping protocol to the URL of the proxy (e.g.
        #: {'http': 'foo.bar:3128'}) to be used on each
        #: :class:`Request <Request>`.
        self.proxies = {}

        #: Event-handling hooks.
        self.hooks = requests.hooks.default_hooks()

        # Default connection adapters.
        self.adapters = requests.compat.OrderedDict()
        self.mount('ftp://', FTPAdapter())
        self.mount('ftps://', FTPAdapter())
        self.mount('sftp://', FTPAdapter())
        self.mount('file://', FTPAdapter())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getstate__(self):
        return dict((attr, getattr(self, attr, None)) for attr in self.__attrs__)

    def __setstate__(self, state):
        for attr, value in state.items():
            setattr(self, attr, value)

    def prepare_request(self, request):
        """Constructs a :class:`PreparedRequest <PreparedRequest>` for
        transmission and returns it. The :class:`PreparedRequest` has settings
        merged from the :class:`Request <Request>` instance and those of the
        :class:`Session`.

        :param request: :class:`Request` instance to prepare with this
            session's settings.
        """

        # Set environment's basic authentication if not explicitly set.
        auth = request.auth
        if self.trust_env and not auth and not self.auth:
            auth = requests.utils.get_netrc_auth(request.url)

        p = requests.models.PreparedRequest()
        p.prepare(
            method=request.method.upper(),
            url=request.url,
            hooks=merge_hooks(request.hooks, self.hooks),
        )
        return p

    def request(self, method, url=None,
                
        # Request parameters
        data=None,
        params=None,
        auth=None,
        hooks=None,

        # Session parameters
        timeout=None,
        proxies=None,
        verify=None,
        cert=None):
        """Constructs a :class:`Request <Request>`, prepares it and sends it.
        Returns :class:`Response <Response>` object.

        :param method: method for the new :class:`Request` object.
        :param url: URL for the new :class:`Request` object.
        :param params: (optional) Dictionary or bytes to be sent in the query
            string for the :class:`Request`.
        :param data: (optional) Dictionary or bytes to send in the body of the
            :class:`Request`.
        :param headers: (optional) Dictionary of HTTP Headers to send with the
            :class:`Request`.
        :param cookies: (optional) Dict or CookieJar object to send with the
            :class:`Request`.
        :param files: (optional) Dictionary of 'filename': file-like-objects
            for multipart encoding upload.
        :param auth: (optional) Auth tuple or callable to enable
            Basic/Digest/Custom HTTP Auth.
        :param timeout: (optional) Float describing the timeout of the
            request.
        :param allow_redirects: (optional) Boolean. Set to True by default.
        :param proxies: (optional) Dictionary mapping protocol to the URL of
            the proxy.
        :param stream: (optional) whether to immediately download the response
            content. Defaults to ``False``.
        :param verify: (optional) if ``True``, the SSL cert will be verified.
            A CA_BUNDLE path can also be provided.
        :param cert: (optional) if String, path to ssl client cert file (.pem).
            If Tuple, ('cert', 'key') pair.
        """

        method = str(method)

        # Create the request.
        req = requests.Request(
            method = method.upper(),
            url = url,
            data = data or {},
            params = params or {},
            auth = auth,
            hooks = hooks,
        )
        
        # Prepare the request.
        preq = self.prepare_request(req)
        proxies = merge_setting(proxies, self.proxies)
        verify = merge_setting(verify, self.verify)
        cert = merge_setting(cert, self.cert)

        # Send the request.
        send_kwargs = {
            'timeout': timeout,
            'proxies': proxies,
            'verify': verify,
            'cert': cert,
        }
        resp = self.send(preq, **send_kwargs)
        return resp

    def send(self, request, **kwargs):
        """Send a given PreparedRequest."""
        # Set defaults that the hooks can utilize to ensure they always have
        # the correct parameters to reproduce the previous request.
        kwargs.setdefault('proxies', self.proxies)
        kwargs.setdefault('verify', self.verify)
        kwargs.setdefault('cert', self.cert)

        # It's possible that users might accidentally send a Request object.
        # Guard against that specific failure case.
        if not isinstance(request, requests.PreparedRequest):
            raise ValueError('You can only send PreparedRequests.')

        # Set up variables needed for resolve_redirects and dispatching of hooks

        # Get the appropriate adapter to use
        adapter = self.get_adapter(url=request.url)

        # Start time (approximately) of the request
        start = datetime.utcnow()

        # Send the request
        r = adapter.send(request, **kwargs)

        # Total elapsed time of the request (approximately)
        r.elapsed = datetime.utcnow() - start

        # Response manipulation hooks
        r = dispatch_hook('response', request.hooks, r, **kwargs)

        # Resolve redirects if allowed.
        history = []

        # Shuffle things around if there's history.
        if history:
            # Insert the first (original) request at the start
            history.insert(0, r)
            # Get the last request made
            r = history.pop()
            r.history = tuple(history)

        return r

    def close(self):
        """Closes all adapters and as such the session"""
        for v in self.adapters.values():
            v.close()

    def get_adapter(self, url):
        """Returns the appropriate connnection adapter for the given URL."""
        for (prefix, adapter) in self.adapters.items():

            if url.lower().startswith(prefix):
                return adapter

        # Nothing matches :-/
        #raise InvalidSchema("No connection adapters were found for '%s'" % url)

    def mount(self, prefix, adapter):
        """Registers a connection adapter to a prefix.

        Adapters are sorted in descending order by key length."""

        self.adapters[prefix] = adapter
        keys_to_move = [k for k in self.adapters if len(k) < len(prefix)]

        for key in keys_to_move:
            self.adapters[key] = self.adapters.pop(key)






















    # ftplib.FTP.retrbinary
    # ftplib.FTP.retrlines
    def get(self, url, **kwargs):
        """Sends a RETR request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('RETR', url, **kwargs)

    # ftplib.FTP.storbinary
    # ftplib.FTP.storlines
    def put(self, url, data=None, append=False, unique=False, **kwargs):
        """Sends a STOR request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('STOR', url, data=data, **kwargs)

    def abort(self, **kwargs):
        """Sends a ABOR request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('ABOR', **kwargs)

    def connect(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        # TODO: parse URL into (host, port)
        return self.request('__CONNECT', url, **kwargs)

    def cwd(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', False)
        return self.request('CWD', url, **kwargs)

    def delete(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('DELE', url, **kwargs)

    def feature(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('FEAT', url, **kwargs)

    def help(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', False)
        return self.request('HELP', url, **kwargs)

    def login(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('__LOGIN', url, **kwargs)

    def makeport(self, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('PORT', **kwargs)

    def makepasv(self, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('PASV', **kwargs)

    def makeeprt(self, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('EPRT', **kwargs)

    def makeepsv(self, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('EPSV', **kwargs)

    def mkd(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('MKD', url, **kwargs)

    def options(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('OPTS', url, **kwargs)

    def pwd(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        kwargs.setdefault('allow_redirects', False)
        return self.request('PWD', url, **kwargs)

    def quit(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('QUIT', url, **kwargs)

    def rmd(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('RMD', url, **kwargs)

    def rename(self, url, desturl, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('__RENAME', url, desturl, **kwargs)

    def size(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('SIZE', url, **kwargs)

    def stat(self, url, **kwargs):
        """Sends a HEAD request. Returns :class:`FTPResponse` object.

        :param url: URL for the new :class:`Request` object.
        :param \*\*kwargs: Optional arguments that ``request`` takes.
        """

        return self.request('STAT', url, **kwargs)
