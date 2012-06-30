from __future__ import unicode_literals

from .parser import get_parser
from .version import VERSION
from .config import GlobalConfig, CLIENT_KEY, CLIENT_SECRET
from .colors import Colors
from ..client import RESTClient
from ..client.errors import RESTAPIError, AuthenticationNotConfigured
from ..client.auth import BasicAuth, NullAuth, OAuth2Auth
from ..packages.bytesconverter import bytes2human

import sys
import codecs
import os
import json
import subprocess
import re
import time
import shutil
import getpass
import requests
import urllib2
import datetime
import calendar

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
            422: self.error_unprocessable,
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
            self.client.authenticator.pre_refresh_callback = self.pre_refresh_token
            self.client.authenticator.post_refresh_callback = self.post_refresh_token
        elif self.global_config.get('apikey'):
            access_key, secret = self.global_config.get('apikey').split(':')
            self.client.authenticator = BasicAuth(access_key, secret)

    def pre_refresh_token(self, req):
        self.info('Refreshing OAuth2 token...')

    def post_refresh_token(self, res):
        self.info('Refreshed OAuth2 token')
        self.global_config.data['token']['access_token'] = res['access_token']
        self.global_config.data['token']['refresh_token'] = res['refresh_token']
        self.global_config.save()
        return True

    def run(self, args):
        p = get_parser(self.cmd)
        args = p.parse_args(args)
        self.load_local_config(args)
        cmd = 'cmd_{0}'.format(args.cmd)
        if not hasattr(self, cmd):
            raise NotImplementedError('cmd not implemented: "{0}"'.format(cmd))
        try:
            return getattr(self, cmd)(args)
        except AuthenticationNotConfigured:
            self.error('CLI authentication is not configured. Run `{0} setup` now.'.format(self.cmd))
        except RESTAPIError, e:
            handler = self.error_handlers.get(e.code, self.default_error_handler)
            handler(e)
        except KeyboardInterrupt:
            pass
        except urllib2.URLError as e:
            self.error('Accessing dotCloud API failed: {0}'.format(str(e)))

    def ensure_app_local(self, args):
        if args.application is None:
            self.die('No application specified. '
                     'Run this command from an application directory '
                     'or specify which application to use with --application.')

    def app_local(func):
        def wrapped(self, args):
            self.ensure_app_local(args)
            return func(self, args)
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

    def load_local_config(self, args):
        try:
            io = open('.dotcloud/config')
            config = json.load(io)
            if not args.application:
                args.application = config['application']
            self.config = config
        except IOError, e:
            self.config = {}

    def destroy_local_config(self):
        try:
            shutil.rmtree('.dotcloud')
        except:
            pass

    def die(self, message=None, stderr=False):
        if message is not None:
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
            '{message}' \
            .format(c=self.colors, message=message)

    def default_error_handler(self, e):
        self.error('An unknown error has occurred: {0}'.format(e))
        self.error('If the problem persists, please e-mail ' \
            'support@dotcloud.com {0}' \
            .format('and mention Trace ID "{0}"'.format(e.trace_id)
                if e.trace_id else ''))
        self.die()

    def error_authen(self, e):
        self.die("Authentication Error: {0}".format(e.code))

    def error_authz(self, e):
        self.die("Authorization Error: {0}".format(e.desc))

    def error_not_found(self, e):
        self.die("Not Found: {0}".format(e.desc))

    def error_unprocessable(self, e):
        self.die(e.desc)

    def error_server(self, e):
        self.error('Server Error: {0}'.format(e.desc))
        self.error('If the problem persists, please e-mail ' \
            'support@dotcloud.com {0}' \
            .format('and mention Trace ID "{0}"'.format(e.trace_id)
                if e.trace_id else ''))
        self.die()

    def cmd_check(self, args):
        # TODO Check ~/.dotcloud stuff
        try:
            self.info('Checking the authentication status')
            res = self.client.get('/me')
            self.success('Client is authenticated as ' \
                '{c.bright}{username}{c.reset}' \
                .format(username=res.item['username'], c=self.colors))
        except:
            raise
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
        form = {
            'username': username,
            'password': password,
            'grant_type': 'password',
            'client_id': credential['key']
        }
        res = requests.post(url, data=form,
            auth=(credential['key'], credential['secret']))
        res.raise_for_status()
        return json.loads(res.text)

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
        self.destroy_local_config()

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
                raise
        self.success('Destroyed.')
        if args.service is None:
            if self.config.get('application') == args.application:
                self.destroy_local_config()

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
            url = '/me/applications/{0}/services/{1}/aliases' \
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
            self.info('Variables for application {0}'.format(args.application))
            var = self.client.get(url).item
            for name in sorted(var.keys()):
                print '='.join((name, var.get(name)))
        elif args.subcmd == 'set':
            self.info('Setting {0} (application {1})'.format(
                ', '.join(args.values), args.application))
            patch = {}
            for pair in args.values:
                key, val = pair.split('=')
                patch[key] = val
            self.client.patch(url, patch)
            deploy = True
        elif args.subcmd == 'unset':
            self.info('Un-setting {0} (application {1})'.format(
                ', '.join(args.variables), args.application))
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
        self.info('Scaling application {0}'.format(args.application))
        def round_memory(value):
            # Memory scaling has to be performed in increments of 32M
            # Let's align max(step, value) to closest upper or lower step boundary.
            step = 32 * (1024 * 1024)
            return ((max(step, value) & ~(step / 2 - 1)) + step - 1) & ~(step - 1)

        for svc in args.services:
            try:
                if svc.action == 'instances':
                    url = '/me/applications/{0}/services/{1}/instances' \
                        .format(args.application, svc.name)
                    self.info('Changing instances of {0} to {1}'.format(
                        svc.name, svc.original_value))
                    self.client.put(url, {'instances': svc.value})
                elif svc.action == 'memory':
                    memory = round_memory(svc.value)
                    self.info('Changing memory of {0} to {1}B'.format(
                        svc.name, bytes2human(memory)))
                    url = '/me/applications/{0}/services/{1}/memory' \
                        .format(args.application, svc.name)
                    self.client.put(url, {'memory': memory})
            except RESTAPIError as e:
                if e.code == requests.codes.bad_request:
                    self.die('Failed to scale {0} of "{1}": {2}'.format(
                        svc.action, svc.name, e))
                raise

        ret = 0
        # If we changed the number of instances of any service, then we need
        # to trigger a deploy
        if any(svc.action == 'instances' for svc in args.services):
            ret = self.deploy(args.application)
            print 'ret', ret

        if ret == 0:
            self.success('Successfully scaled {0} to {1}'.format(args.application,
                ' '.join(['{0}:{1}={2}'.format(svc.name, svc.action,
                    svc.original_value)
                    for svc in args.services])))

    @app_local
    def cmd_info(self, args):
        self.info('Application {0}'.format(args.application))
        url = '/me/applications/{0}/services'.format(args.application)
        res = self.client.get(url)

        if not res.items:
            self.warning('It seems you haven\'t deployed your application.')
            self.warning('Run {0} push to deploy and see the information about your stack. '.format(self.cmd))
            return

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
        if args.service:
            urls = self.get_url(args.application, args.service)
            if urls:
                print urls[-1]['url']
        else:
            for (service, urls) in self.get_url(args.application).items():
                print '{0}: {1}'.format(service, urls[-1]['url'])

    @app_local
    def cmd_open(self, args):
        import webbrowser

        if args.service:
            urls = self.get_url(args.application, args.service)
            if urls:
                webbrowser.open(urls[-1]['url'])
        else:
            urls = self.get_url(args.application)
            if not urls:
                self.die('No URLs found for the application')
            if len(urls) > 1:
                self.die('More than one service exposes an URL. ' \
                    'Please specify the name of the one you want to open: {0}' \
                    .format(', '.join(urls.keys())))
            webbrowser.open(urls.values()[0][-1]['url'])

    def get_url(self, application, service=None, type='http'):
        if service is None:
            urls = {}
            url = '/me/applications/{0}/services'.format(application)
            res = self.client.get(url)
            for service in res.items:
                instance = service['instances'][0]
                u = [p for p in instance.get('ports', []) if p['name'] == type]
                if len(u) > 0:
                    urls[service['name']] = u
            return urls
        else:
            url = '/me/applications/{0}/services/{1}'.format(application,
                service)
            res = self.client.get(url)
            instance = res.item['instances'][0]
            return [p for p in instance.get('ports', []) if p['name'] == type]

    @app_local
    def cmd_deploy(self, args):
        self.deploy(args.application, clean=args.clean, revision=args.revision)

    def _select_endpoint(self, endpoints, protocol):
        try:
            return [endpoint for endpoint in endpoints
                    if endpoint['protocol'] == protocol][0]['endpoint']
        except IndexError:
            self.die('Unable to find {0} endpoint in [{1}]'.format(
                protocol,
                ', '.join(endpoint['protocol'] for endpoint in endpoints))
                )

    @app_local
    def cmd_push(self, args):
        url = '/me/applications/{0}/push-endpoints'.format(args.application)
        endpoints = self.client.get(url).items
        rsync_endpoint = self._select_endpoint(endpoints, 'rsync')
        self.push_with_rsync(args, rsync_endpoint, args.path)
        return self.deploy(args.application, clean=args.clean)

    def push_with_rsync(self, args, rsync_endpoint, local_dir='.'):
        if not local_dir.endswith('/'):
            local_dir += '/'
        self.info('Syncing code from "{0}" to application {1}'.format(local_dir,
            args.application))
        url = self.parse_url(rsync_endpoint)
        ssh = ' '.join(self.common_ssh_options + ['-o', 'LogLevel=QUIET'])
        ssh += ' -p {0}'.format(url['port'])
        excludes = ('*.pyc', '.git', '.hg')
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
        response = self.client.put(url, {'revision': revision, 'clean': clean})
        deploy_trace_id = response.trace_id
        deploy_id = response.item['deploy_id']

        try:
            res = self._stream_deploy_logs(application, deploy_id,
                    deploy_trace_id=deploy_trace_id, follow=True)
            if res != 0:
                return res
        except KeyboardInterrupt:
            self.error('You\'ve closed your log stream with Ctrl-C, ' \
                'but the deployment is still running in the background.')
            self.error('If you aborted because of an error ' \
                '(e.g. the deployment got stuck), please e-mail\n' \
                'support@dotcloud.com and mention this trace ID: {0}'
                .format(deploy_trace_id))
            self.error('If you want to continue following your deployment, ' \
                    'try:\n{0} logs deploy -d {1}'.format(
                        os.path.basename(sys.argv[0]), deploy_id))
            self.die()
        urls = self.get_url(application)
        if urls:
            self.success('Application is live at {c.bright}{url}{c.reset}' \
                .format(url=urls.values()[-1][-1]['url'], c=self.colors))
        else:
            self.success('Application is live')
        return 0

    @property
    def common_ssh_options(self):
        return [
            'ssh', '-t',
            '-i', self.global_config.key,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PasswordAuthentication=no',
            '-o', 'ServerAliveInterval=10',
        ]

    def _escape(self, s):
        for c in ('`', '$', '"'):
            s = s.replace(c, '\\' + c)
        return s

    def parse_service_instance(self, args):
        if '.' in args.service_or_instance:
            service_name, instance_id = args.service_or_instance.split('.', 2)
            try:
                instance_id = int(instance_id)
                if instance_id < 0:
                    raise ValueError('value should be >= 0')
            except ValueError as e:
                self.die('Unable to parse instance number: {0}'.format(e))

        else:
            service_name = args.service_or_instance
            instance_id = 0
        return service_name, instance_id

    def get_ssh_endpoint(self, args):
        service_name, instance_id = self.parse_service_instance(args)

        url = '/me/applications/{0}/services/{1}'.format(args.application,
                service_name)
        service = self.client.get(url).item

        try:
            instances = sorted(service['instances'], key=lambda i: i['container_id'])
            instance = instances[instance_id]
        except IndexError:
            self.die('Not Found: Service ({0}) instance #{1} does not exist'.format(
                service['name'], instance_id))

        try:
            ssh_endpoint = filter(lambda p: p['name'] == 'ssh',
                    instance.get('ports', []))[0]['url']
        except (IndexError, KeyError):
            self.die('No ssh endpoint for service ({0}) instance #{1}'.format(
                service['name'], instance_id))

        url = self.parse_url(ssh_endpoint)
        if None in [url['host'], url['port']]:
            self.die('Invalid ssh endpoint "{0}" ' \
                    'for service ({1}) instance #{2}'.format(
                        ssh_endpoint, service['name'], instance_id))

        return dict(service=service['name'],
                instance=instance_id, host=url['host'], port=url['port'],
                user=url.get('user', 'dotcloud'),
                )

    def spawn_ssh(self, ssh_endpoint, cmd_args=None):
        ssh_args = self.common_ssh_options + [
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'LogLevel=ERROR',
            '-l', ssh_endpoint['user'],
            '-p', str(ssh_endpoint['port']),
            ssh_endpoint['host']
        ]
        if cmd_args:
            ssh_args.append('--')
            ssh_args.extend(cmd_args)
        return subprocess.Popen(ssh_args)

    @app_local
    def cmd_run(self, args):
        ssh_endpoint = self.get_ssh_endpoint(args)
        if args.command:
            cmd_args = [args.command] + args.args
            self.info('Executing "{0}" on service ({1}) instance #{2} (application {3})'.format(
                ' '.join(cmd_args), ssh_endpoint['service'],
                ssh_endpoint['instance'], args.application))
        else:
            cmd_args = None
            self.info('Opening a shell on service ({0}) instance #{1} (application) {2}'.format(
                    ssh_endpoint['service'], ssh_endpoint['instance'],
                    args.application))
        return self.spawn_ssh(ssh_endpoint, cmd_args).wait()

    def parse_url(self, url):
        m = re.match('^(?P<scheme>[^:]+)://((?P<user>[^@]+)@)?(?P<host>[^:/]+)(:(?P<port>\d+))?(?P<path>/.*)?$', url)
        if not m:
            raise ValueError('"{url}" is not a valid url'.format(url=url))
        ret = m.groupdict()
        return ret

    @app_local
    def cmd_restart(self, args):
        service_name, instance_id = self.parse_service_instance(args)

        url = '/me/applications/{0}/services/{1}/restart?instance={2}' \
            .format(args.application, service_name, instance_id)
        try:
            self.client.post(url)
        except RESTAPIError as e:
            if e.code == 404:
                self.die('Service ({0}) instance #{1} not found'.format(
                    service_name, instance_id))
            raise
        self.info('Service ({0}) instance #{1} of application {2} is being restarted.'.format(
            service_name, instance_id, args.application))

    @app_local
    def cmd_logs(self, args):
        cmd = 'cmd_logs_{0}'.format(args.logs)
        if not hasattr(self, cmd):
            raise NotImplementedError('cmd not implemented: "{0}"'.format(cmd))
        return getattr(self, cmd)(args)

    def iso_dtime_local(self, strdate):
        bt = time.strptime(strdate, "%Y-%m-%dT%H:%M:%S.%fZ")
        ts = calendar.timegm(bt)
        dt = datetime.datetime.fromtimestamp(ts)
        return dt

    def cmd_activity(self, args):
        if not args.all and args.application:
            url = '/me/applications/{0}/activity'.format(args.application)
        else:
            url = '/me/activity'
        print 'time', ' ' * 14,
        print 'category action   application.service (details)'
        for activity in self.client.get(url).items:
            print '{ts:19} {category:8} {action:8}'.format(
                    ts=str(self.iso_dtime_local(activity['created_at'])),
                    **activity),
            category = activity['category']
            if category == 'app':
                print '{application}'.format(**activity),
                if activity['action'] == 'deploy':
                    print '(revision={revision} build={build})' \
                        .format(**activity),
            elif category == 'alias':
                print '{application}.{service}'.format(**activity),
                print '(cname={alias})'.format(**activity),
            elif category == 'service':
                print '{application}.{service}'.format(**activity),
                action = activity['action']
                if action == 'scale':
                    scale = activity['scale']
                    if scale == 'instances':
                        print '(instances={0})'.format(activity['value']),
                    elif scale == 'memory':
                        print '(memory={0})'.format(
                                bytes2human(activity['value'])
                                ),
            user = activity.get('user')
            if user is not None and not user['self']:
                print '/by <{0}>'.format(user.get('username')),
            print

    def _logs_deploy_list(self, args):
        deployments = self.client.get('/me/applications/{0}/logs/deployments'.format(
            args.application))
        print 'deployment date', ' ' * 3,
        print 'revision', ' ' * 15, 'deploy_id [application {0}]'.format(args.application)
        deploy_id = None
        previous_deploy_id = None
        for log in deployments.items:
            previous_deploy_id = deploy_id
            ts = self.iso_dtime_local(log['created_at'])
            deploy_id = log['deploy_id']
            print '{0} {1:24} {2}'.format(ts, log['revision'], deploy_id)

        selfcmd = os.path.basename(sys.argv[0])
        if previous_deploy_id:
            print '-- <hint> display previous deployment\'s logs:'
            print '{0} logs deploy -d {1}'.format(selfcmd, previous_deploy_id)
        print '-- <hint> display latest deployment\'s logs:'
        print '{0} logs deploy'.format(selfcmd)

    def _stream_formated_logs(self, url, filter_svc=None, filter_inst=None):
        response = self.client.get(url, streaming=True)
        meta = response.item
        last_ts = None
        for log in response.items:
            raw_ts = log.get('created_at')
            if raw_ts is not None:
                ts = self.iso_dtime_local(log['created_at'])
                if last_ts is None or (last_ts.day != ts.day
                        or last_ts.month != ts.month
                        or last_ts.year != ts.year
                        ):
                    print '- {0} ({1} deployment, deploy_id={2})'.format(ts.date(),
                            meta['application'], meta['deploy_id'])
                last_ts = ts
                line = '{0}: '.format(ts.time())
            else:
                line = ''

            tags = ''
            svc = log.get('service')
            inst = log.get('instance')

            if filter_svc:
                if filter_svc != svc:
                    continue
                if (filter_inst is not None and inst is not None
                        and filter_inst != int(inst)):
                    continue

            if svc is not None:
                if inst is not None:
                    tags = '[{0}.{1}] '.format(svc, inst)
                else:
                    tags = '[{0}] '.format(svc)
            else:
                tags = '--> '

            line += '{0}{1}'.format(tags, log['message'])
            if log.get('level') == 'ERROR':
                line = '{c.red}{0}{c.reset}'.format(line, c=self.colors)

            yield log, line

    def _stream_deploy_logs(self, app, did=None, filter_svc=None,
            filter_inst=None, deploy_trace_id=None, follow=False, lines=None):
        url = '/me/applications/{0}/logs/deployments/{1}?stream'.format(app,
                did or 'latest')

        if follow:
            url += '&follow'

        if lines is not None:
            url += '&lines={0}'.format(lines)

        for log, formated_line, in self._stream_formated_logs(url, filter_svc,
                filter_inst):

            if log.get('partial', False):
                print formated_line, '\r',
                sys.stdout.flush()
            else:
                print formated_line

            status = log.get('status')
            if status is not None:
                if status == 'deploy_end':
                    return 0
                if status == 'deploy_fail':
                    return 2

        if not follow:
            return 0

        self.error('The connection was lost, ' \
                'but the deployment is still running in the background.')
        if deploy_trace_id is not None:
            self.error('If this message happen too often, please e-mail\n' \
                    'support@dotcloud.com and mention this trace ID: {0}'
                .format(deploy_trace_id))
        self.error('if you want to continue following your deployment, ' \
                'try:\n{0} logs deploy -d {1}'.format(
                    os.path.basename(sys.argv[0]), did))
        self.die()

    def cmd_logs_deploy(self, args):
        if args.list:
            return self._logs_deploy_list(args)

        filter_svc = None
        filter_inst = None
        if args.service:
            parts = args.service.split('.')
            filter_svc = parts[0]
            if len(parts) > 1:
                filter_inst = int(parts[1])

        follow = not args.no_follow if filter_svc is None else False
        return self._stream_deploy_logs(args.application, did=args.d,
                filter_svc=filter_svc, filter_inst=filter_inst,
                follow=follow, lines=args.lines)

    def cmd_logs_app(self, args):
        filter_svc = None
        filter_inst = None
        if args.service:
            parts = args.service.split('.')
            filter_svc = parts[0]
            if len(parts) > 1:
                filter_inst = int(parts[1])

        url = '/me/applications/{0}/logs/application?stream'.format(
                args.application)

        if not args.no_follow:
            url += '&follow'

        if args.lines is not None:
            url += '&lines={0}'.format(args.lines)

        if filter_svc is not None:
            url += '&service={0}'.format(filter_svc)
            if filter_inst is not None:
                url += '&instance={0}'.format(filter_inst)

        for log, formated_line, in self._stream_formated_logs(url, filter_svc,
                filter_inst):

            if log.get('partial', False):
                print formated_line, '\r',
                sys.stdout.flush()
            else:
                print formated_line
