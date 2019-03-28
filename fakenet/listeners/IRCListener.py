import logging

import sys
import os

import threading
import SocketServer

import ssl
import socket

import BannerFactory

from . import *

RPL_WELCOME = '001'
SRV_WELCOME = "Welcome to FakeNet."

BANNERS = {
    'generic': 'Welcome to IRC - {servername} - %a %b %d %H:%M:%S {tz} %Y',
    'debian-ircd-irc2': (
        '17/10/2011 11:50\n' +
        '                         [ Debian GNU/Linux ]\n' +
        '|------------------------------------------------------------------------|\n' +
        '| This is Debian\'s default IRCd server configuration for irc2.11. If you |\n' +
        '| see this and if you are the server administrator, just edit ircd.conf  |\n' +
        '| and ircd.motd in /etc/ircd.                                            |\n' +
        '|                                     Martin Loschwitz, 1st January 2005 |\n' +
        '|------------------------------------------------------------------------|\n')
}

class IRCListener(object):

    def taste(self, data, dport):

        # All possible commands are included to account for unanticipated 
        # malware behavior
        commands = [ 
            'ADMIN', 'AWAY', 'CAP', 'CNOTICE', 'CPRIVMSG', 'CONNECT', 'DIE', 
            'ENCAP', 'ERROR', 'HELP', 'INFO', 'INVITE', 'ISON', 'JOIN', 'KICK', 
            'KILL', 'KNOCK', 'LINKS', 'LIST', 'LUSERS', 'MODE', 'MOTD', 
            'NAMES', 'NAMESX', 'NICK', 'NOTICE', 'OPER', 'PART', 'PASS', 
            'PING', 'PONG', 'PRIVMSG', 'QUIT', 'REHASH', 'RESTART', 'RULES', 
            'SERVER', 'SERVICE', 'SERVLIST', 'SQUERY', 'SQUIT', 'SETNAME', 
            'SILENCE', 'STATS', 'SUMMON', 'TIME', 'TOPIC', 'TRACE', 'UHNAMES', 
            'USER', 'USERHOST', 'USERIP', 'USERS', 'VERSION', 'WALLOPS', 
            'WATCH', 'WHO', 'WHOIS', 'WHOWAS' 
            ]

        # ubuntu xchat uses 8001
        ports = [194, 6667, range(6660, 7001), 8001]
        
        confidence = 1 if dport in ports else 0
        
        data = data.lstrip()

        # remove optional prefix
        if data.startswith(':'):
            data = data.split(' ')[0]

        for command in commands:
            if data.startswith(command):
                confidence += 2
                continue

        return confidence

    def __init__(self,
            config,
            name='IRCListener',
            logging_level=logging.INFO,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)
        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.name = 'IRC'
        
        self.port = self.config.get('port', 6667)
        self.logger.debug('PORT: %s', self.port)

        self.logger.debug('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.iteritems():
            self.logger.debug('  %10s: %s', key, value)

    def start(self):
        self.logger.debug('Starting...')
        self.server = ThreadedTCPServer((self.local_ip, int(self.config['port'])), ThreadedTCPRequestHandler)

        self.banner = self.genBanner()
        self.server.listener = self
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.servername = self.config.get('servername', 'localhost')

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def genBanner(self):
        bannerfactory = BannerFactory.BannerFactory()
        return bannerfactory.genBanner(self.config, BANNERS)

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get('timeout', 10)))

        self.server.logger.info('Client connected')

        try:

            while True:

                data = self.request.recv(1024)

                if not data:
                    break

                elif len(data) > 0:

                    for line in data.split("\n"):

                        if line and len(line) > 0:

                            if ' ' in line:
                                cmd, params = line.split(' ', 1)
                            else:
                                cmd, params = line, ''

                            handler = getattr(self, 'irc_%s' % (cmd.upper()), self.irc_DEFAULT)
                            handler(cmd, params)

        except socket.timeout:
            self.server.logger.warning('Connection timeout')

        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror or msg)

        except Exception, e:
            self.server.logger.error('Error: %s', e)

    def irc_DEFAULT(self, cmd, params):
        self.server.logger.info('Client issued an unknown command %s %s', cmd, params)      
        self.irc_send_server("421", "%s :Unknown command" % cmd)          

    def irc_NICK(self, cmd, params):

        self.nick = params

        banner = self.server.listener.banner

        self.irc_send_server("001", "%s :%s" % (self.nick, banner))
        self.irc_send_server("376", "%s :End of /MOTD command." % self.nick)

    def irc_USER(self, cmd, params):
        if params.count(' ') == 3:

            user, mode, unused, realname = params.split(' ', 3)
            self.user = user
            self.mode = mode
            self.realname = realname
            self.request.sendall('')

    def irc_PING(self, cmd, params):
        self.request.sendall(":%s PONG :%s" % (self.server.servername, self.server.servername))


    def irc_JOIN(self, cmd, params):

        if ' ' in params:
            channel_names, channel_keys = params.split(' ')

        else:
            channel_names = params
            channel_keys  = None

        for i, channel_name in enumerate(channel_names.split(',')):

            if channel_keys:
                self.server.logger.info('Client %s is joining channel %s with key %s', self.nick, channel_name, channel_keys.split(',')[i])
            else:
                self.server.logger.info('Client %s is joining channel %s with no key', self.nick, channel_name)


            self.request.sendall(":root TOPIC %s :FakeNet\r\n" % channel_name)
            self.irc_send_client("JOIN :%s" % channel_name)

            nicks = ['botmaster', 'bot', 'admin', 'root', 'master']
            self.irc_send_server("353", "%s = %s :%s" % (self.nick, channel_name, ' '.join(nicks)))
            self.irc_send_server("366", "%s %s :End of /NAMES list" % (self.nick, channel_name))

            # Send a welcome message
            self.irc_send_client_custom('botmaster', 'botmaster', self.server.servername, "PRIVMSG %s %s" % (channel_name, "Welcome to the channel! %s" % self.nick))


    def irc_PRIVMSG(self, cmd, params):

        if ' ' in params:
            target, message = params.split(' ', 1)

            self.server.logger.info('Client sent message "%s" to %s', message, target)

            # Echo the message in the channel back to the user
            if target[0] in ['#', '$']:
                self.irc_send_client_custom('botmaster', 'botmaster', self.server.servername, "PRIVMSG %s %s" % (target, message))

            # Echo the private message back to the user
            else:
                self.irc_send_client_custom(target, target, self.server.servername, "PRIVMSG %s %s" % (self.nick, message))


    def irc_NOTICE(self, cmd, params):
        pass

    def irc_PART(self, cmd, params):
        pass

    def irc_send_server(self, code, message):
        self.request.sendall(":%s %s %s\r\n" % (self.server.servername, code, message))

    def irc_send_client(self, message):
        self.irc_send_client_custom(self.nick, self.user, self.server.servername, message)

    def irc_send_client_custom(self, nick, user, servername, message):
        self.request.sendall(":%s!%s@%s %s\r\n" % (nick, user, servername, message))

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    # Avoid [Errno 98] Address already in use due to TIME_WAIT status on TCP
    # sockets, for details see:
    # https://stackoverflow.com/questions/4465959/python-errno-98-address-already-in-use
    allow_reuse_address = True

###############################################################################
# Testing code
def test(config):
    pass


def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '6667', 'usessl': 'No', 'timeout': 10, 'servername': 'localhost' }

    listener = IRCListener(config)
    listener.start()

    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    ###########################################################################
    # Run tests
    test(config)

if __name__ == '__main__':
    main()
