#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# tor_bridgeckeck.py: script to check whether default tor bridges are active.
# Copyright © 2012-2015 Jérémy Bobbio <lunar@debian.org>
# Copyright © 2014-2015 Dumindu Buddhika <dumindukarunathilaka@gmail.com>
#
# Code to check a bridge is reused from original code by
# Jérémy Bobbio <lunar@debian.org> with modifications.
# A link to the code
# <https://anonscm.debian.org/cgit/users/lunar/check_tor.git/tree/check_tor.py>
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
PREFERENCES_FILE = 'Browser/TorBrowser/Data/Browser/profile.default/' \
                   'preferences/extension-overrides.js'
CLIENT_TRANSPORT_PLUGINS_PATH = 'Browser/TorBrowser/Tor/' \
                                'PluggableTransports/'

import sys
import errno
import os
import shutil
import tempfile
import pycurl
import re
import stem
import stem.connection
import stem.control
import stem.process
import argparse


class IdentityMismatch(Exception):
    RE = r'\[warn\] Tried connecting to router at \S+ but identity key was' \
         r' not as expected'


class ClientTransportIssue(Exception):
    RE = r'\[warn\] We were supposed to connect to bridge \S+ using ' \
         r'pluggable transport'


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

        self.controller = stem.control.Controller.from_socket_file(
            self.control_socket_path())
        self.controller.authenticate()

        try:
            self.socks_addr = self.controller.get_info(
                'net/listeners/socks')[1:-1]  # skip " at begining and end
        except stem.ControllerError, exc:
            raise UnableToDetermineSOCKSPort(
                "Unable to determine Tor SOCKS port")

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
        c = pycurl.Curl()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.PROXY, 'socks5h://%s' % socks_addr)
        c.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
        c.setopt(pycurl.WRITEFUNCTION, self.write_url_content)

        if DEBUG:
            c.setopt(pycurl.VERBOSE, 1)
            c.setopt(pycurl.DEBUGFUNCTION, self.print_curl_debug)
        c.perform()
        return self._url_content


class BridgeTest(ConnectivityTest):
    def __init__(self, transport, bridge_conf='', datadir=None):
        super(BridgeTest, self).__init__()
        self.datadir = datadir
        self.bridge_conf = bridge_conf
        self.nickname = None
        self.transport = transport

    def handle_circ(self, event):
        if DEBUG:
            print "CIRC: %s" % event
        if stem.CircBuildFlag.IS_INTERNAL in event.build_flags:
            return
        if event.status == stem.CircStatus.EXTENDED:
            self.nickname = event.path[0][1]

    def run(self, transport_config):

        config = {
            'UseBridges': '1',
            'Bridge': self.bridge_conf,
            }

        config.update(transport_config.get(self.transport, {}))

        with Tor(config, self.datadir) as tor:
            print 'Tor instance created'
            tor.controller.add_event_listener(
                self.handle_circ, stem.control.EventType.CIRC)

            url_content = self.get_url(
                tor.socks_addr, 'https://www.torproject.org/')
            if 'Tor Project: Anonymity Online' not in url_content:
                print 'Unexpected URL content using bridge %s' % (self.nickname)
                return

            print 'Successfully built a circuit using bridge ' \
                  '%s' % (self.nickname)


def obtain_bridges(file):

    bridge_lines = list()

    for line in file:
        if 'extensions.torlauncher.default_bridge.' in line:
            linesegments = line.split("\"")
            bridge_lines.append(linesegments[3].strip())

    return bridge_lines


def generate_report(bridges, results, path):
    if path is None:
        path = ""

    report_file = open(os.path.join(path, "report.html"), "w")

    report_file.write("""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
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
    report_file.write("""<table style="width:100%">
          <caption>Status of the bridges</caption>
          <tr>
            <th>Bridge</th>
            <th>Status</th>
          </tr>
          """)

    for bridge in bridges:

        report_file.write("""
        <tr>
                <td>""" + bridge + """</td>
                <td>""" + results[bridge] + """</td>
              </tr>
        """)

    report_file.write("""
        </table>

    """)
    report_file.write("""
        </body>
        </html>""")
    report_file.close()

    print "Report created."


def make_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("tbpath",
                        help="Path to the Tor Browser binary")
    parser.add_argument("--report", help="Path to the generated report")
    return parser


def get_transport_config(tbpath):

    # paths for each of the proxy client location
    transport_configs = {
        'obfs2': {'ClientTransportPlugin': 'obfs2 exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'obfsproxy.bin --managed'},
        'obfs3': {'ClientTransportPlugin': 'obfs3 exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'obfsproxy.bin --managed'},
        'obfs4': {'ClientTransportPlugin': 'obfs4 exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'obfs4proxy'},
        'fte': {'ClientTransportPlugin': 'fte exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'fteproxy.bin --managed'},
        'scramblesuit': {'ClientTransportPlugin': 'scramblesuit exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'obfsproxy.bin --managed'},
        'flashproxy': {'ClientTransportPlugin': 'flashproxy exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'flashproxy-client --register :0 :8888'},
        'meek': {'ClientTransportPlugin': 'meek exec ' + os.path.join(tbpath, CLIENT_TRANSPORT_PLUGINS_PATH) + 'meek-client'},
        }

    return transport_configs


def main():
    parser = make_parser()
    args = parser.parse_args()

    default_bridge_file = None
    try:
        default_bridge_file = open(os.path.join(args.tbpath, PREFERENCES_FILE), 'Ur')
    except:
        print 'Preferences file not found. Please set the Tor Browser binary ' \
              'location correctly.'
        sys.exit(1)

    bridges = obtain_bridges(default_bridge_file)  # list of default  bridges
    results = dict()

    for bridge_line in bridges:

        test = BridgeTest(bridge_line.split()[0], bridge_line.strip())

        print 'Checking Bridge: ' + bridge_line

        try:
            transport_config = get_transport_config(args.tbpath)
            test.run(transport_config)
            results[bridge_line] = "live"
        except UnableToDetermineSOCKSPort, ex:
            print '%s' % ex
            sys.exit(1)
        except Exception, ex:
            if str(ex).strip() == "Process terminated: Bridge line did not parse. " \
                                  "See logs for details.":
                print '%s' % ex
                print 'Bridge line format in the preferences file is incorrect.'
                sys.exit(1)
            results[bridge_line] = "Connection timed out"
            print '%s' % ex

        print ''

    generate_report(bridges, results, args.report)

if __name__ == '__main__':
    main()
