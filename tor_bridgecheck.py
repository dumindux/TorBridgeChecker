#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# tor_bridgeckeck.py: script to check whether default tor bridges are active.
# Copyright © 2014-2015 Dumindu Buddhika <dumindukarunathilaka@gmail.com>
#
# Code to check whether a given bridge can be used to build a circuit is reused from original
# code by Jérémy Bobbio <lunar@debian.org> with modifications . A link to the code
# is here<https://anonscm.debian.org/cgit/users/lunar/check_tor.git/tree/check_tor.py>
#
# This program is free software: you can redistribute it and/or modify
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

DEBUG = False


import sys
import os

preferences_file='/Browser/TorBrowser/Data/Browser/profile.default/preferences/extension-overrides.js'


OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3
DEPENDENT = 4

import errno
import os
import shutil
import signal
import tempfile
import time
import pycurl
import random
import re
import stem
import stem.connection
import stem.control
import stem.process
import argparse


#paths for each of the proxy client location
TRANSPORT_CONFIG = {
    'obfs2': {'ClientTransportPlugin': 'obfs2 exec /usr/bin/obfsproxy --managed'},
    'obfs3': {'ClientTransportPlugin': 'obfs3 exec /usr/bin/obfs4proxy'},
    'obfs4': {'ClientTransportPlugin': 'obfs4 exec /usr/bin/obfs4proxy'},
    'fte': {'ClientTransportPlugin': 'fte exec /usr/bin//fteproxy.bin --managed'},
    'scramblesuit':{'ClientTransportPlugin': 'scramblesuit exec /usr/bin/obfsproxy --managed' },
    'flashproxy' : {'ClientTransportPlugin': 'flashproxy exec /usr/bin/flashproxy-client --register :0 :9000'},
    'meek': {'ClientTransportPlugin': 'meek exec /usr/bin/meek-client'},
}

class IdentityMismatch(Exception):
    RE = r'\[warn\] Tried connecting to router at \S+ but identity key was not as expected'

class ClientTransportIssue(Exception):
    RE = r'\[warn\] We were supposed to connect to bridge \S+ using pluggable transport'

class UnableToBuildCircuit(Exception):
    pass

class UnableToDetermineSOCKSPort(Exception):
    pass

class Tor(object):
    def __init__(self, extra_config, datadir=None, completion_percent=100):
        self.popen = None
        self.controller = None
        self.pid = None
        self.socks_addr = None
        self.datadir_is_temp = False
        self.datadir = datadir
        self.completion_percent = completion_percent
        self.extra_config = extra_config

    def __enter__(self):


        if not self.datadir:
            self.datadir_is_temp = True
            self.datadir = tempfile.mkdtemp()

        config = dict(self.extra_config)
        config.update({
            'DataDirectory': self.datadir,
            'ControlSocket': self.control_socket_path(),
            'SocksPort': 'auto',
            })


        self.popen = stem.process.launch_tor_with_config(
            config=config,
            completion_percent=self.completion_percent,
            init_msg_handler=self.handle_init_msg,
            take_ownership=True)

        self.controller = stem.control.Controller.from_socket_file(self.control_socket_path())
        self.controller.authenticate()

        try:
            self.socks_addr = self.controller.get_info('net/listeners/socks')[1:-1] # skip " at begining and end
        except stem.ControllerError, exc:
            raise UnableToDetermineSOCKSPort("Unable to determine Tor SOCKS port")

        # We want nicknames in circuit events
        self.controller.enable_feature("VERBOSE_NAMES")

        return self

    def __exit__(self, type, value, traceback):
        if self.controller:
            self.controller.close()
            self.controller = None
        if self.popen:
            try:
                self.popen.poll()
                if not self.popen.returncode:
                    self.popen.kill()
                    self.popen.communicate()
            except OSError, ex:
                if ex.errno != errno.ESRCH:
                    raise
            self.popen = None
        if self.datadir_is_temp:
            shutil.rmtree(self.datadir)
            self.datadir = None
            self.datadir_is_temp = False

    def handle_init_msg(self, msg):
        if DEBUG:
            print msg
        msg = re.sub(r'\A[^[]+ ', '', msg)
        if re.match(IdentityMismatch.RE, msg):
            raise IdentityMismatch(msg)
        if re.match(ClientTransportIssue.RE, msg):
            raise ClientTransportIssue(msg)

    def control_socket_path(self):
        return os.path.join(self.datadir, 'control')

# abstract test class
class ConnectivityTest(object):
    def __init__(self, datadir=None):
        self._url_content = ''

    def write_url_content(self, buf):
        self._url_content += buf

    def print_curl_debug(self, debug_type, debug_msg):
        print "pycurl(%d): %s" % (debug_type, debug_msg)

    def get_url(self, socks_addr, url):
        socks_host, socks_port = socks_addr.split(':')
        c = pycurl.Curl()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.PROXY, socks_host)
        c.setopt(pycurl.PROXYPORT, int(socks_port))
        # XXX: if pycurl was up to date, we should use something like this:
        #c.setopt(pycurl.PROXY, 'socks5h://%s' % socks_addr)
        # XXX: but we need to use the following 2, which leaks.
        # it should at least be PROXY_SOCKS5_HOSTNAME instead
        c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
        c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
        c.setopt(pycurl.WRITEFUNCTION, self.write_url_content)


        if DEBUG:
            c.setopt(pycurl.VERBOSE, 1)
            c.setopt(pycurl.DEBUGFUNCTION, self.print_curl_debug)
        c.perform()
        return self._url_content

class BridgeTest(ConnectivityTest):
    def __init__(self, transport,bridge_conf='', datadir=None):
        super(BridgeTest, self).__init__()
        self.datadir = datadir
        self.bridge_conf=bridge_conf
        self.nickname = None
        self.transport=transport

    def handle_circ(self, event):
        if DEBUG:
            print "CIRC: %s" % event
        if stem.CircBuildFlag.IS_INTERNAL in event.build_flags:
            return
        if event.status == stem.CircStatus.EXTENDED:
            self.nickname = event.path[0][1]

    def run(self):

        config = { 'UseBridges': '1',
                   'Bridge': self.bridge_conf,
                   }

        config.update(TRANSPORT_CONFIG.get(self.transport, {}))

        with Tor(config, self.datadir) as tor:
            print 'Tor instance created'
            tor.controller.add_event_listener(self.handle_circ, stem.control.EventType.CIRC)

            url_content = self.get_url(tor.socks_addr, 'https://www.torproject.org/')
            if 'Tor Project: Anonymity Online' not in url_content:
                print 'WARNING: unexpected URL content using bridge %s' % (self.nickname)
                return

            print 'OK: successfully built a circuit using bridge %s' % (self.nickname)


def obtain_bridges(file):

    bridge_lines=list()

    for line in file:
        if 'extensions.torlauncher.default_bridge.' in line:
            linesegments=line.split("\"")
            bridge_lines.append(linesegments[3].strip())

    return bridge_lines

def generate_report(bridges,results,path):
    file=open(path+"/report.html","w")

    file.write("""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        "http://www.w3.org/TR/html4/loose.dtd">
        <html>
        <head>
            <title>Bridge Status Report</title>
            <style>
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 5px;
                    text-align: left;
            }
            </style>
        </head>
        <body>
        """)
    file.write("""<table style="width:100%">
          <caption>Status of the bridges</caption>
          <tr>
            <th>Bridge</th>
            <th>Status</th>
          </tr>
          """)

    for bridge in bridges:

        file.write("""
        <tr>
                <td>"""+bridge+"""</td>
                <td>"""+results[bridge]+ """</td>
              </tr>
        """)

    file.write("""
        </table>

    """)
    file.write("""
        </body>
        </html>""")
    file.close()

def make_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("tbbpath",
                        help="Path to the tor browser bundle")
    parser.add_argument("--rpath",help="Path to the generated report")
    return parser

def main():
    parser = make_parser()
    args = parser.parse_args()

    default_bridge_file = None
    try:
        default_bridge_file=open(args.tbbpath+preferences_file,'Ur')
    except:
        print 'Preferences file not found. Please set the tor browser bundle location correctly.'
        sys.exit(UNKNOWN)


    bridges=obtain_bridges(default_bridge_file)  #list of default  bridges
    results=dict()

    for bridge_line in bridges:

        test = BridgeTest(bridge_line.split()[0],bridge_line.strip())

        print 'Checking Bridge: '+bridge_line

        try:
            test.run()
            results[bridge_line]="live"
        except UnableToDetermineSOCKSPort, ex:
            print 'UNKNOWN: %s' % ex
            sys.exit(UNKNOWN)
        except Exception, ex:
            if str(ex).strip() == "Process terminated: Bridge line did not parse. See logs for details.":
                print 'UNKNOWN: %s' % ex
                print 'Bridge line format in the preferences file is incorrect.'
                sys.exit(UNKNOWN)
            results[bridge_line]="connection timed out"
            print 'CRITICAL: %s' % ex

        print ''

    generate_report(bridges,results,args.rpath)

if __name__ == '__main__':
    main()