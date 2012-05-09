from .parser import get_parser
from .version import VERSION
from .config import GlobalConfig, CLIENT_KEY, CLIENT_SECRET
from .colors import Colors
from ..client import RESTClient
from ..client.errors import RESTAPIError, AuthenticationNotConfigured
from ..client.auth import BasicAuth, NullAuth, OAuth2Auth

import sys
import codecs
import os
import json
import subprocess
import re
import time
import shutil
import getpass
import urllib2
import urllib
import base64
import datetime

class CLI(object):
    __version__ = VERSION
    def __init__(self, debug=False, colors=None, endpoint=None):
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout)
        self.client = RESTClient(endpoint=endpoint, debug=debug)
        self.debug = debug
        self.colors = Colors(colors)
        self.error_handlers = {
            401: self.error_authen,
            403: self.error_authz,
            404: self.error_not_found,
            500: self.error_server,
        }
        self.global_config = GlobalConfig()
        self.setup_auth()
        self.cmd = os.path.basename(sys.argv[0])

    def setup_auth(self):
        if self.global_config.get('token'):
            token = self.global_config.get('token')
            client = self.global_config.get('client')
            self.client.authenticator = OAuth2Auth(access_token=token['access_token'],
                                                   refresh_token=token['refresh_token'],
                                                   scope=token.get('scope'),
                                                   client_id=CLIENT_KEY,
                                                   client_secret=CLIENT_SECRET,
                                                   token_url=token['url'])
            self.client.authenticator.refresh_callback = lambda res: self.refresh_token(res)
        elif self.global_config.get('apikey'):
            access_key, secret = self.global_config.get('apikey').split(':')
            self.client.authenticator = BasicAuth(access_key, secret)

    def refresh_token(self, res):
        self.info('Refreshed OAuth2 token')
        self.global_config.data['token']['access_token'] = res['access_token']
        self.global_config.data['token']['refresh_token'] = res['refresh_token']
        self.global_config.save()
        return True

    def show_trace(self, id):
        print '--> TraceID: ' + id

    def run(self, args):
        p = get_parser(self.cmd)
        args = p.parse_args(args)
        self.load_config(args)
        if args.trace:
            self.client.trace = lambda id: self.show_trace(id)
        cmd = 'cmd_{0}'.format(args.cmd)
        if not hasattr(self, cmd):
            raise NotImplementedError('cmd not implemented: "{0}"'.format(cmd))
        try:
            getattr(self, cmd)(args)
        except AuthenticationNotConfigured:
            self.error('CLI authentication is not configured. Run `{0} setup` now.'.format(self.cmd))
        except RESTAPIError, e:
            handler = self.error_handlers.get(e.code, self.default_error_handler)
            handler(e)
        except KeyboardInterrupt:
            pass
        except urllib2.URLError as e:
            self.error('Accessing dotCloud API failed: {0}'.format(str(e)))
        finally:
            if args.trace and self.client.trace_id:
                self.show_trace(self.client.trace_id)

    def ensure_app_local(self, args):
        if args.application is None:
            self.die('dotCloud application is not connected. '
                     'Run `{cmd} create <appname>` or `{cmd} connect <appname>`'.format(cmd=self.cmd))

    def app_local(func):
        def wrapped(self, args):
            self.ensure_app_local(args)
            func(self, args)
        return wrapped

    def save_config(self, config):
        dir = '.dotcloud'
        if not os.path.exists(dir):
            os.mkdir(dir, 0700)
        f = open(os.path.join(dir, 'config'), 'w+')
        json.dump(config, f, indent=4)

    def patch_config(self, new_config):
        config = {}
        try:
            io = open('.dotcloud/config')
            config = json.load(io)
        except IOError, e:
            pass
        config.update(new_config)
        self.save_config(config)

    def load_config(self, args):
        try:
            io = open('.dotcloud/config')
            config = json.load(io)
            if not args.application:
                args.application = config['application']
            self.config = config
        except IOError, e:
            self.config = {}

    def destroy_config(self):
        try:
            shutil.rmtree('.dotcloud')
        except:
            pass

    def die(self, message, stderr=False):
        if stderr:
            print >>sys.stderr, message
        else:
            self.error(message)
        sys.exit(1)

    def prompt(self, prompt, noecho=False):
        method = getpass.getpass if noecho else raw_input
        input = method(prompt + ': ')
        return input

    def confirm(self, prompt, default='n'):
        choice = ' [Yn]' if default == 'y' else ' [yN]'
        input = raw_input(prompt + choice + ': ').lower()
        if input == '':
            input = default
        return input == 'y'

    def error(self, message):
        print '{c.red}{c.bright}Error:{c.reset} {message}' \
            .format(c=self.colors, message=message)

    def info(self, message):
        print '{c.blue}{c.bright}==>{c.reset} {message}' \
            .format(c=self.colors, message=message)

    def warning(self, message):
        print '{c.yellow}{c.bright}Warning:{c.reset} {message}' \
            .format(c=self.colors, message=message)

    def success(self, message):
        print '{c.green}{c.bright}==>{c.reset} ' \
            '{c.bright}{message}{c.reset}' \
            .format(c=self.colors, message=message)

    def default_error_handler(self, e):
        self.die("Unhandled exception: {0}".format(e))

    def error_authen(self, e):
        self.die("Authentication Error: {0}".format(e.code))

    def error_authz(self, e):
        self.die("Authorization Error: {0}".format(e.desc))

    def error_not_found(self, e):
        self.die("Not Found: {0}".format(e.desc))

    def error_server(self, e):
        #FIXME
        if self.client.trace_id:
            self.info('TraceID: {0}'.format(self.client.trace_id))
        self.die('Server Error: {0}'.format(e.desc))

    def cmd_check(self, args):
        # TODO Check ~/.dotcloud stuff
        try:
            self.info('Checking the authentication status')
            res = self.client.get('/me')
            self.success('Client is authenticated as {0}'.format(res.item['username']))
        except:
            self.die('Authentication failed. Run `{cmd} setup` to redo the authentication'.format(cmd=self.cmd))
        self.get_keys()

    def cmd_setup(self, args):
        client = RESTClient(endpoint=self.client.endpoint)
        client.authenticator = NullAuth()
        urlmap = client.get('/auth/discovery').item
        username = self.prompt('dotCloud username')
        password = self.prompt('Password', noecho=True)
        credential = {'token_url': urlmap.get('token'),
            'key': CLIENT_KEY, 'secret': CLIENT_SECRET}
        try:
            token = self.authorize_client(urlmap.get('token'), credential, username, password)
        except Exception as e:
            self.die('Username and password do not match. Try again.')
        token['url'] = credential['token_url']
        config = GlobalConfig()
        config.data = {'token': token}
        config.save()
        self.global_config = GlobalConfig()  # reload
        self.setup_auth()
        self.get_keys()
        self.success('dotCloud authentication is complete! You are recommended to run `{cmd} check` now.'.format(cmd=self.cmd))

    def authorize_client(self, url, credential, username, password):
        req = urllib2.Request(url)
        user_pass = '{0}:{1}'.format(urllib2.quote(credential['key']), urllib2.quote(credential['secret']))
        basic_auth = base64.b64encode(user_pass).strip()
        req.add_header('Authorization', 'Basic {0}'.format(basic_auth))
        form = {
            'username': username,
            'password': password,
            'grant_type': 'password',
            'client_id': credential['key']
        }
        req.add_data(urllib.urlencode(form))
        res = urllib2.urlopen(req)
        return json.load(res)

    def get_keys(self):
        res = self.client.get('/me/private_keys')
        try:
            key = res.items[0]['private_key']
            self.global_config.save_key(key)
        except (KeyError, IndexError):
            self.die('Retrieving push keys failed. You might have to run `{0} check` again'.format(self.cmd))

    def cmd_list(self, args):
        res = self.client.get('/me/applications')
        for app in sorted(res.items, key=lambda x: x['name']):
            if app['name'] == args.application:
                print '* ' + self.colors.green(app['name'])
            else:
                print '  ' + app['name']

    def cmd_create(self, args):
        self.info('Creating a new application called "{0}"'.format(args.application))
        url = '/me/applications'
        try:
            res = self.client.post(url, { 'name': args.application, 'repository': args.repo })
        except RESTAPIError as e:
            if e.code == 409:
                self.die('Application "{0}" already exists.'.format(args.application))
            else:
                self.die('Creating app "{0}" failed: {1}'.format(args.application, e))
        self.success('Application "{0}" created.'.format(args.application))
        if self.confirm('Connect the current directory to "{0}"?'.format(args.application), 'y'):
            self._connect(args.application)

    def cmd_connect(self, args):
        url = '/me/applications/{0}'.format(args.application)
        try:
            res = self.client.get(url)
            self._connect(args.application)
        except RESTAPIError:
            self.die('Application "{app}" doesn\'t exist. Try `{cmd} create <appname>`.' \
                         .format(app=args.application, cmd=self.cmd))

    @app_local
    def cmd_disconnect(self, args):
        self.info('Disconnecting the current directory from "{0}"'.format(args.application))
        self.destroy_config()

    @app_local
    def cmd_destroy(self, args):
        if args.service is None:
            what_destroy = 'application'
            to_destroy = args.application
            url = '/me/applications/{0}'.format(args.application)
        else:
            what_destroy = 'service'
            to_destroy = '{0}.{1}'.format(args.application, args.service)
            url = '/me/applications/{0}/services/{1}'.format(args.application, args.service)

        if not self.confirm('Destroy the {0} "{1}"?'.format(what_destroy, to_destroy)):
            return
        self.info('Destroying "{0}"'.format(to_destroy))
        try:
            res = self.client.delete(url)
        except RESTAPIError as e:
            if e.code == 404:
                self.die('The {0} "{1}" does not exist.'.format(what_destroy, to_destroy))
            else:
                self.die('Destroying the {0} "{1}" failed: {1}'.format(what_destroy, to_destroy, e))
        self.success('Destroyed.')
        if args.service is None:
            if self.config.get('application') == args.application:
                self.destroy_config()

    def _connect(self, application):
        self.info('Connecting with the application "{0}"'.format(application))
        self.save_config({
            'application': application,
            'version': self.__version__
        })
        self.success('Connected.')

    @app_local
    def cmd_app(self, args):
        print args.application

    @app_local
    def cmd_service(self, args):
        if args.subcmd == 'list':
            url = '/me/applications/{0}/services'.format(args.application)
            res = self.client.get(url)
            for service in res.items:
                print '{0} (instances: {1})'.format(service['name'], len(service['instances']))

    @app_local
    def cmd_alias(self, args):
        if args.subcmd == 'list':
            url = '/me/applications/{0}/services'.format(args.application)
            res = self.client.get(url)
            for svc in res.items:
                url = '/me/applications/{0}/services/{1}/aliases'\
                    .format(args.application, svc.get('name'))
                res = self.client.get(url)
                for alias in res.items:
                    print '{0}: {1}'.format(svc.get('name'), alias.get('alias'))
        elif args.subcmd == 'add':
            url = '/me/applications/{0}/services/{2}/aliases' \
                .format(args.application, args.service)
            res = self.client.post(url, {'alias': args.alias})
            self.success('Alias "{0}" created for "{1}"'.format(
                args.alias, args.service))
        elif args.subcmd == 'rm':
            url = '/me/applications/{0}/services/{1}/aliases/{2}' \
                .format(args.application, args.service, args.alias)
            self.client.delete(url)
            self.success('Alias "{0}" deleted from "{1}"'.format(
                args.alias, args.service))

    @app_local
    def cmd_var(self, args):
        url = '/me/applications/{0}/variables'.format(args.application)
        deploy = None
        if args.subcmd == 'list':
            var = self.client.get(url).item
            for name in sorted(var.keys()):
                print '='.join((name, var.get(name)))
        elif args.subcmd == 'set':
            patch = {}
            for pair in args.values:
                key, val = pair.split('=')
                patch[key] = val
            self.client.patch(url, patch)
            deploy = True
        elif args.subcmd == 'unset':
            patch = {}
            for name in args.variables:
                patch[name] = None
            self.client.patch(url, patch)
            deploy = True
        else:
            self.die('Unknown sub command {0}'.format(subcmd), stderr=True)
        if deploy:
            self.deploy(args.application)

    @app_local
    def cmd_scale(self, args):
        instances = {}
        for svc in args.services:
            name, value = svc.split('=', 2)
            value = int(value)
            instances[name] = value
        for name, value in instances.items():
            url = '/me/applications/{0}/services/{1}/instances' \
                .format(args.application, name)
            self.info('Changing instances of {0} to {1}'.format(name, value))
            try:
                self.client.put(url, {'instances': value})
            except RESTAPIError, e:
                if e.code == 400:
                    self.die('Failed to scale "{0}" service: {1}'.format(name, e))
                raise
        self.deploy(args.application)

    @app_local
    def cmd_info(self, args):
        try:
            url = '/me/applications/{0}/services'.format(args.application)
            res = self.client.get(url)
        except RESTAPIError as e:
            if e.code == 404:
                self.warning('It seems you haven\'t deployed your application.')
                self.warning('Run {0} push to deploy and see the information about your stack. '.format(self.cmd))
                return
            else:
                raise
        for service in res.items:
            print '{0} (instances: {1})'.format(service['name'], len(service['instances']))
            self.dump_service(service['instances'][0], indent=2)

        url = '/me/applications/{0}'.format(args.application)
        res = self.client.get(url)
        repo = res.item.get('repository')
        revision = res.item.get('revision', None)

        print '--------'
        if repo:
            print 'Repository: ' + repo
        print 'Revision: ' + (revision if revision else '(Unknown)')

    def dump_service(self, instance, indent=0):
        def show(string):
            buf = ' ' * indent
            print buf + string
        show('runtime_config:')
        for (k, v) in instance['config'].iteritems():
            show('  {0}: {1}'.format(k, v))
        show('build_config:')
        for (k, v) in instance['build_config'].iteritems():
            show('  {0}: {1}'.format(k, v))
        show('URLs:')
        for port in instance['ports']:
            show('  {0}: {1}'.format(port['name'], port['url']))

    @app_local
    def cmd_url(self, args):
        def cb(service, urls):
            print '{0}: {1}'.format(service['name'], urls[0]['url'])
        self.get_url(args.application, cb)

    def get_url(self, application, cb, type='http'):
        url = '/me/applications/{0}/services'.format(application)
        res = self.client.get(url)
        for service in res.items:
            instance = service['instances'][0]
            u = [p for p in instance.get('ports', []) if p['name'] == type]
            if len(u) > 0:
                cb(service, u)

    @app_local
    def cmd_deploy(self, args):
        self.deploy(args.application, clean=args.clean, revision=args.revision)

    @app_local
    def cmd_push(self, args):
        url = '/me/applications/{0}/push-url'.format(args.application)
        res = self.client.get(url)
        push_url = res.item.get('url')
        self.rsync_code(push_url)
        self.deploy(args.application, clean=args.clean)

    def rsync_code(self, push_url, local_dir='.'):
        self.info('Syncing code from {0} to {1}'.format(local_dir, push_url))
        url = self.parse_url(push_url)
        ssh = ' '.join(self.common_ssh_options)
        ssh += ' -p {0}'.format(url['port'])
        excludes = ('*.pyc', '.git', '.hg')
        if not local_dir.endswith('/'):
            local_dir += '/'
        ignore_file = os.path.join(local_dir, '.dotcloudignore')
        ignore_opt = ('--exclude-from', ignore_file) if os.path.exists(ignore_file) else tuple()
        rsync = ('rsync', '-lpthrvz', '--delete', '--safe-links') + \
                 tuple('--exclude={0}'.format(e) for e in excludes) + \
                 ignore_opt + \
                 ('-e', ssh, local_dir,
                  '{user}@{host}:{dest}/'.format(user=url['user'],
                                                 host=url['host'], dest=url['path']))
        try:
            ret = subprocess.call(rsync, close_fds=True)
            if ret!= 0:
                self.die('SSH connection failed')
            return ret
        except OSError:
            self.die('rsync failed')

    def deploy(self, application, clean=False, revision=None):
        self.info('Deploying {0}'.format(application))
        url = '/me/applications/{0}/revision'.format(application)
        self.client.put(url, {'revision': revision, 'clean': clean})
        url = '/me/applications/{0}/build_logs'.format(application)
        while True:
            res = self.client.get(url)
            for item in res.items:
                source = item.get('source', 'api')
                if source == 'api':
                    source = '-->'
                else:
                    source = '[{0}]'.format(source)
                line = u'{0} {1} {2}'.format(
                    self.iso_dtime_local(item['timestamp']).strftime('%H:%M:%S'),
                    source,
                    item['message'])
                print line
            next = res.find_link('next')
            if not next:
                break
            url = next.get('href')
            time.sleep(3)
        def display_url(service, urls):
            self.success('Application is live at {0}'.format(urls[0]['url']))
        self.get_url(application, display_url)

    @app_local
    def cmd_ssh(self, args):
        instance = 0
        if '.' in args.service:
            svc, instance = args.service.split('.', 2)
        else:
            svc = args.service
        try:
            instance = int(instance)
        except ValueError:
            self.die('usage: {0} ssh service[.N]'.format(self.cmd),
                stderr=True)
        url = '/me/applications/{0}/services/{1}'.format(args.application, svc)
        res = self.client.get(url)
        for service in res.items:
            try:
                ports = service['instances'][instance].get('ports', [])
                u = [p for p in ports if p['name'] == 'ssh']
                if len(u) > 0:
                    self.run_ssh(u[instance]['url'], '$SHELL').wait()
            except IndexError:
                self.die('Not Found: Service instance {0}.{1} does not exist'.format(svc, instance))

    @app_local
    def cmd_run(self, args):
        # TODO refactor with cmd_ssh
        url = '/me/applications/{0}/services/{1}'.format(args.application,
            args.service)
        res = self.client.get(url)
        for service in res.items:
            ports = service['instances'][0].get('ports', [])
            u = [p for p in ports if p['name'] == 'ssh']
            if len(u) > 0:
                self.run_ssh(u[0]['url'], ' '.join(args.command)).wait()

    @property
    def common_ssh_options(self):
        return (
            'ssh', '-t',
            '-i', self.global_config.key,
            '-o', 'LogLevel=QUIET',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PasswordAuthentication=no',
            '-o', 'ServerAliveInterval=10'
        )

    def _escape(self, s):
        for c in ('`', '$', '"'):
            s = s.replace(c, '\\' + c)
        return s

    def run_ssh(self, url, cmd, **kwargs):
        self.info('Connecting to {0}'.format(url))
        res = self.parse_url(url)
        options = self.common_ssh_options + (
            '-l', res.get('user', 'dotcloud'),
            '-p', res.get('port'),
            res.get('host'),
            'bash -l -c "{0}"'.format(self._escape(cmd))
        )
        return subprocess.Popen(options, **kwargs)

    def parse_url(self, url):
        m = re.match('^(?P<scheme>[^:]+)://((?P<user>[^@]+)@)?(?P<host>[^:/]+)(:(?P<port>\d+))?(?P<path>/.*)?$', url)
        if not m:
            raise ValueError('"{url}" is not a valid url'.format(url=url))
        ret = m.groupdict()
        return ret

    @app_local
    def cmd_restart(self, args):
        url = '/me/applications/{0}/services/{1}/reboots' \
            .format(args.application, args.service)
        try:
            self.client.post(url)
        except RESTAPIError as e:
            if e.code == 404:
                self.die('Service {0} not found'.format(args.service))
        self.info('Service {0} will be restarted.'.format(args.service))

    def cmd_logs(self, args):
        print args.logs
        cmd = 'cmd_logs_{0}'.format(args.logs)
        if not hasattr(self, cmd):
            raise NotImplementedError('cmd not implemented: "{0}"'.format(cmd))
        getattr(self, cmd)(args)

    def iso_dtime_local(self, strdate):
        bt = time.strptime(strdate, "%Y-%m-%dT%H:%M:%S.%fZ")
        ts = time.mktime(bt)
        dt = datetime.datetime.utcfromtimestamp(ts)
        return dt

    def cmd_history(self, args):
        if not args.all and args.application:
            url = '/me/applications/{0}/activity'.format(args.application)
        else:
            url = '/me/activity'
        print 'time', ' ' * 14,
        print 'category action application.service (details)'
        for activity in self.client.get(url).items:
            print '{ts:19} {category:8} {action:6}'.format(
                    ts=self.iso_dtime_local(activity['created_at']),
                    **activity),
            category = activity['category']
            if category == 'app':
                print '{application}'.format(**activity),
                if activity['action'] == 'deploy':
                    print '(revision={revision} build={build})' \
                        .format(**activity)
                else:
                    print
            elif category == 'alias':
                print '{application}.{service}'.format(**activity),
                print '(cname={alias})'.format(**activity)
