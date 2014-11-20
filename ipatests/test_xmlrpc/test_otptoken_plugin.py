# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Test the `ipalib/plugins/otptoken.py` module.
"""

import base64
import hashlib
import os
import urlparse
import uuid
import random
import string
import subprocess

from datetime import datetime, timedelta

import pyotp

from ipalib import api
from xmlrpc_test import XMLRPC_test
from ipatests.util import assert_deepequal
from ipapython.version import API_VERSION

from pytest import fixture, skip, mark
usefixtures = mark.usefixtures
parametrize = mark.parametrize
xfail = mark.xfail

class Token(dict):
    @property
    def type(self):
        return self[u'type'].upper()

    def __repr__(self):
        prefixes = ['ipatoken' + x for x in ('totp', 'hotp', 'otp', '')]

        args = {}
        for k, v in self.items():
            for prefix in prefixes:
                if k.startswith(prefix):
                    k = k[len(prefix):]
                    break

            if k in ('key', 'uniqueid', 'owner'):
                continue

            args[k] = v

        return "%s(%s:%d|%d%s%s)" % (
            args.pop('type').upper(),
            args.pop('algorithm'),
            args.pop('digits'),
            args.pop('counter', args.pop('timestep', 0)),
            ':' if self.type == 'TOTP' else '',
            str(args.pop('clockoffset', '')),
        ) + repr(args)

    def otp(self, at=0):
        kwargs = {}
        if self.type == u"TOTP":
            kwargs['interval'] = self[u'ipatokentotptimestep']

            offset = timedelta(0, self.get(u'ipatokentotpclockoffset', 0))
            span = timedelta(0, kwargs['interval']) * at
            at = datetime.now() + offset + span
        elif self.type == u"HOTP":
            if at < 0:
                return None
            at += self.get(u'ipatokenhotpcounter', 0)

        otp = getattr(pyotp, self.type)(
            base64.b32encode(self[u'ipatokenotpkey']),
            self[u'ipatokenotpdigits'],
            getattr(hashlib, self[u'ipatokenotpalgorithm']),
            **kwargs
        )

        code = str(otp.at(at))
        while len(code) < otp.digits:
            code = "0" + code

        return code

    def expected(self):
        result = {}
        for k, v in self.items():
            if isinstance(v, bool):
                result[k] = (unicode(v).upper(),)
            elif isinstance(v, int):
                result[k] = (unicode(v),)
            else:
                result[k] = (v,)

        result[u'type'] = result[u'type'][0].upper()
        result[u'dn'] = u'ipatokenuniqueid=%s,cn=otp,dc=example,dc=com'
        result[u'dn'] %= self[u'ipatokenuniqueid']

        return {
            u'summary': u'Added OTP token "%s"' % self[u'ipatokenuniqueid'],
            u'result': result,
            u'value': self[u'ipatokenuniqueid'],
        }

    def path(self, user):
        return '/%s@%s:%s' % (user, api.env.realm, self[u'ipatokenuniqueid'])

    def query(self, user):
        types = {
            "HOTP": {u'counter': self.get(u'ipatokenhotpcounter')},
            "TOTP": {u'period': self.get(u'ipatokentotptimestep')},
        }

        query = {
            u'algorithm': self.get(u'ipatokenotpalgorithm'),
            u'issuer': u'%s@%s' % (user, api.env.realm),
            u'digits': self.get(u'ipatokenotpdigits'),
            u'secret': base64.b32encode(self[u'ipatokenotpkey']),
        }

        query.update(types.get(self.type, {}))
        query = {k: (unicode(v),) for k, v in query.items()}
        return query


def cmd(cmd, *args, **kwargs):
    return api.Command[cmd](*args, version=API_VERSION, **kwargs)


#def login(uid, pwd):
#    dn = DN(('uid', uid), api.env.container_user, api.env.basedn)
#    conn = ldap.initialize('ldap://' + api.env.host)
#    try:
#        conn.simple_bind_s(str(dn), pwd)
#        setattr(login, "fails", 0)
#    except ldap.INVALID_CREDENTIALS as e:
#        setattr(login, "fails", getattr(login, "fails", 0) + 1)
#        if getattr(login, "fails", 0) > 3:
#            cmd('user_unlock', uid)
#            setattr(login, "fails", 0)
#        raise


class AuthenticationError(Exception):
    pass


def kinit(uid, pwd, newpwd=None):
    data = pwd + '\n'
    if newpwd is not None:
        data += newpwd + '\n' + newpwd + '\n'

    argv = ['/usr/bin/kinit', '%s@%s' % (uid, api.env.realm)]
    if newpwd is None:
        ccache = subprocess.Popen(
            ['/usr/bin/klist'],
            stdout=subprocess.PIPE
        ).communicate()[0].split('\n')[0].split(': ')[1]

        argv.insert(1, ccache)
        argv.insert(1, '-T')

    p = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"KRB5CCNAME": "FILE:/dev/null"}
    )
    out, err = p.communicate(data)
    if p.returncode != 0:
        raise AuthenticationError(out, err)


def login(uid, pwd):
    try:
        kinit(uid, pwd)
        login.fails = 0
    except AuthenticationError:
        login.fails = getattr(login, "fails", 0) + 1
        if login.fails > 3:
            cmd('user_unlock', uid)
            setattr(login, "fails", 0)
        raise


@fixture(scope="module")
def user(request):
    args = [u'tuser1',]
    kwargs = {
        'userpassword': u''.join(random.sample(string.digits + string.letters, 20)),
        'givenname': u'Test',
        'sn': u'User1',
    }

    cmd('user_add', *args, **kwargs)
    request.addfinalizer(lambda: cmd('user_del', *args))

    # Change password
    kinit(args[0], kwargs['userpassword'], kwargs['userpassword'])
    return (args[0], kwargs['userpassword'])


@fixture(scope="module",
                params=[
    ('config_mod', lambda u: ()),
    #('user_mod', lambda u: u[0:1]),
])
def enable(request, user):
    c, a = request.param
    cmd(c, *a(user), ipauserauthtype=(u'otp'))
    request.addfinalizer(lambda: cmd(c, *a(user), ipauserauthtype=()))
    return 'global' if c == 'config_mod' else 'user'


def _token(request, user):
    # Create the token object.
    token = Token(
        ipatokenuniqueid=unicode(uuid.uuid4()),
        ipatokenotpkey=os.urandom(20),
        ipatokenowner=user[0],
        **request.param
    )

    # Add in default values.
    for i in range(len(api.Object['otptoken'].params)):
        param = api.Object['otptoken'].params[i]
        if param.default is not None and param.name:
            token.setdefault(param.name, param.default)

    # Remove defaults that don't apply.
    types = {
        "HOTP": (u'ipatokenhotpcounter',),
        "TOTP": (u'ipatokentotptimestep', u'ipatokentotpclockoffset'),
    }
    for k, names in types.items():
        if k != token[u'type'].upper():
            for name in names:
                del token[name]

    # Add the token.
    result = cmd('otptoken_add', **token)
    request.addfinalizer(lambda: cmd('otptoken_del', token[u'ipatokenuniqueid']))

    # Remove the URI and validate the rest of the return value.
    uri = result.get('result', {}).pop('uri', None)
    assert_deepequal(token.expected(), result)

    # Validate the URI.
    split = urlparse.urlsplit(uri)
    assert split.scheme == u'otpauth'
    assert split.netloc.upper() == token[u'type'].upper()
    assert split.path == token.path(user[0])
    assert_deepequal(token.query(user[0]),
                     urlparse.parse_qs(split.query))

    return token


def _test_2fa_auth(user, token, pwd, at):
    if pwd is None:
        pwd = user[1]

    if isinstance(at, basestring):
        code = at

    else:
        code = token.otp(at)
        if code is None: # Skip invalid test offsets.
            skip('N/A counter offset')

    login(user[0], pwd + code)


class Test1FA:
    PARAMS = (
        (None, ''),               # Password-only
        xfail((None, '123456')),  # Password, code
        xfail(('', '')),          # Nothing
        xfail(('', '123456')),    # Code-only
    )

    @parametrize("pwd,code", PARAMS)
    def test_disabled(self, user, pwd, code):
        if pwd is None:
            pwd = user[1]
    
        login(user[0], pwd + code)

    @usefixtures("enable")
    @parametrize("pwd,code", PARAMS)
    def test_enabled(self, user, pwd, code):
        if pwd is None:
            pwd = user[1]
    
        login(user[0], pwd + code)


@usefixtures("enable")
class TestTokensFull:
    @fixture(scope="class", params=[
        dict(type=u'HOTP', ipatokenhotpcounter=1000),
        #dict(type=u'TOTP', ipatokentotptimestep=60),
        #dict(type=u'TOTP', ipatokentotpclockoffset=30000),
    ])
    def token(self, request, user):
        return _token(request, user)

    @parametrize("pwd,at", (
        #xfail((None, '')),       # Check invalid 1FA
        #xfail((None, '123456')), # Check fake OTP
        #xfail((None, -1000)),    # Check distant past OTP
        #(None, -2),              # Check past OTP
        (None, 0),               # Check current OTP
        #xfail((None, 0)),        # Check duplicate OTP
        #(None, 1),               # Check next OTP
        #(None, 3),               # Check future OTP
        #xfail(('fail', 4)),      # Check bad password
        #xfail(('', 5)),          # Check no password
        #xfail((None, 1000)),     # Check distant future OTP
    ))
    def test(self, user, token, pwd, at):
        return _test_2fa_auth(user, token, pwd, at)


@usefixtures("enable")
class TestTokensBasic:
    @fixture(scope="class", params=(
        dict(type=u'hotp'),
        dict(type=u'HOTP'),
        dict(type=u'totp'),
        dict(type=u'TOTP'),

        #dict(ipatokenotpalgorithm=u'sha1'), # Default
        dict(ipatokenotpalgorithm=u'sha256'),
        dict(ipatokenotpalgorithm=u'sha384'),
        dict(ipatokenotpalgorithm=u'sha512'),

        #dict(ipatokenotpdigits=6), # Default
        dict(ipatokenotpdigits=8),

        dict(ipatokendisabled=False),
        dict(ipatokennotbefore=datetime.now().replace(microsecond=0) - timedelta(1)),
        dict(ipatokennotafter=datetime.now().replace(microsecond=0) + timedelta(1)),
    ))
    def token(self, request, user):
        return _token(request, user)

    def test(self, user, token):
        return _test_2fa_auth(user, token, None, 0)


@usefixtures("enable")
class TestTokensDisabled:
    @fixture(scope="class", params=[
        dict(ipatokendisabled=True),
        dict(ipatokennotbefore=datetime.now().replace(microsecond=0) + timedelta(1)),
        dict(ipatokennotafter=datetime.now().replace(microsecond=0) - timedelta(1)),
    ])
    def token(self, request, user):
        return _token(request, user)

    @parametrize("pwd,at", (
        (None, ''),              # Check 1FA
        xfail((None, '123456')), # Check fake OTP
        xfail((None, 0)),        # Check current OTP
        xfail(('fail', '')),     # Check bad password
        xfail(('', '')),         # Check no password
    ))
    def test(self, user, token, pwd, at):
        return _test_2fa_auth(user, token, pwd, at)


