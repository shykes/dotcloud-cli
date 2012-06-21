import argparse
import sys
from .version import VERSION
from ..packages.bytesconverter import human2bytes

class Parser(argparse.ArgumentParser):
    def error(self, message):
        print >>sys.stderr, 'error: {0}'.format(message)
        self.print_help()
        sys.exit(1)


class ScaleOperation(object):
    def __init__(self, kv):
        if kv.count('=') != 1:
            raise argparse.ArgumentTypeError('Invalid action "{0}"' \
                .format(kv))
        (k, v) = kv.split('=')
        if not v:
            raise argparse.ArgumentTypeError('Invalid value for "{0}"' \
                    .format(k))
        if ':' in k:
            (self.name, self.action) = k.split(':', 1)
        else:
            (self.name, self.action) = (k, 'instances')

        if self.action not in ['instances', 'memory']:
            raise argparse.ArgumentTypeError('Invalid action for "{0}": ' \
                    'Action must be either "instances" or "memory"' \
                    .format(self.action))

        self.original_value = v
        if self.action == 'instances':
            try:
                self.value = int(v)
            except ValueError:
                raise argparse.ArgumentTypeError('Invalid value for "{0}": ' \
                        'Instance count must be a number'.format(kv))
        elif self.action == 'memory':
            # Perform sone sanitization of the memory value
            v = v.upper()
            # Strip the trailing B as human2bytes doesn't handle those
            if v.endswith('B'):
                v = v[:-1]
            if v.isdigit():
                self.value = int(v)
            else:
                try:
                    self.value = human2bytes(v)
                except Exception:
                    raise argparse.ArgumentTypeError('Invalid value for "{0}"' \
                        .format(kv))


def get_parser(name='dotcloud'):

    common_parser = Parser(prog=name, description='dotcloud CLI', add_help=False)
    common_parser.add_argument('--application', '-A', help='specify the application')

    parser = Parser(prog=name, description='dotcloud CLI',
            parents=[common_parser])
    parser.add_argument('--version', '-v', action='version', version='dotcloud/{0}'.format(VERSION))

    subcmd = parser.add_subparsers(dest='cmd')

    subcmd.add_parser('list', help='list applications')

    check = subcmd.add_parser('check', help='Check the installation and authentication')
    setup = subcmd.add_parser('setup', help='Setup the client authentication')

    create = subcmd.add_parser('create', help='Create a new application')
    create.add_argument('application', help='specify the application')
    create.add_argument('--repo')

    conn = subcmd.add_parser('connect', help='Connect a local directory with an existing app')
    conn.add_argument('application', help='specify the application')

    destroy = subcmd.add_parser('destroy', help='Destroy an existing app',
            parents=[common_parser])
    destroy.add_argument('service', nargs='?', help='Specify the service')

    disconnect = subcmd.add_parser('disconnect', help='Disconnect the current directory from dotCloud app')

    app = subcmd.add_parser('app', help='Show the application name linked to the current directory')

    activity = subcmd.add_parser('activity', help='Your recent activity',
            parents=[common_parser])

    activity.add_argument('--all' ,'-a', action='store_true',
            help='Print out your activities among all your applications'
            ' rather than the currently connected or selected one.'
            ' Implicit when not connected to any application')

    info = subcmd.add_parser('info', help='Get information about the application',
            parents=[common_parser])
    info.add_argument('service', nargs='?', help='Specify the service')

    url = subcmd.add_parser('url', help='Show URL for the application',
            parents=[common_parser])
    url.add_argument('service', nargs='?', help='Specify the service')

    open_ = subcmd.add_parser('open', help='Open the application in the browser',
            parents=[common_parser])
    open_.add_argument('service', nargs='?', help='Specify the service')

    run = subcmd.add_parser('run',
            help='Open a shell or run a command inside a service instance',
            parents=[common_parser])
    run.add_argument('service_or_instance',
            help='Open a shell or run the command on the first instance of a ' \
                    'given service (ex: www) or a specific one (ex: www.1)')

    run.add_argument('command', nargs='?',
            help='The command to execute on the service\'s instance. ' \
                    'If not specified, open a shell.')
    run.add_argument('args', nargs=argparse.REMAINDER, metavar='...',
            help='Any arguments to the command')

    push = subcmd.add_parser('push', help='Push the code',
            parents=[common_parser])
    push.add_argument('--clean', action='store_true', help='clean build')

    push_legacy = subcmd.add_parser('push_legacy', help='Push the code (legacy way)',
            parents=[common_parser])
    push_legacy.add_argument('--clean', action='store_true', help='clean build')

    deploy = subcmd.add_parser('deploy', help='Deploy the code',
            parents=[common_parser])
    deploy.add_argument('revision', help='Revision to deploy', default='latest', nargs='?')
    deploy.add_argument('--clean', action='store_true', help='clean build')

    logs = subcmd.add_parser('logs', help='Play with logs',
            parents=[common_parser]).add_subparsers(dest='logs')

    logs_deploy = logs.add_parser('deploy', help='Play with deployments logs',
            epilog='''With no arguments it displays all the logs for the latest
            deployment. If the deployment is not yet done, then follow the
            real-time logs until completion.
            ''', parents=[common_parser])

    service_or_instance = logs_deploy.add_mutually_exclusive_group()
    service_or_instance.add_argument('service', nargs='?',
            help='Filter logs upon a given service (ex: www).'
            ' Can be refined further with --build')
    service_or_instance.add_argument('instance', nargs='?',
            help='Filter logs upon a given service instance (ex: www.0).'
            ' Can be refined further with --build or --install')

    list_or_rev = logs_deploy.add_mutually_exclusive_group()
    list_or_rev.add_argument('--list', action='store_true',
            help='List recently recorded  deployments')
    list_or_rev.add_argument('-d', metavar='deployment_id',
            help='Which recorded deployment to look at (discoverable with --list).'
            ' When not specified, use the latest one.')

#    logs_deploy.add_argument('--build', action='store_true',
#            help='Retrieve only build logs.')
#    logs_deploy.add_argument('--install', action='store_true',
#            help='Retrieve only install logs.')

    logs_deploy.add_argument('--no-follow', '-N', action='store_true',
            help='Do not follow real-time logs')
    logs_deploy.add_argument('--lines', '-n', type=int, metavar='N',
            help='Tail only N logs (before following real-time logs by default)')
#    logs_deploy.add_argument('--head', '-H', type=int, metavar='N',
#            help='Display the first N logs.'
#            ' Wait after real-time logs if needed.'
#            ' If --no-follow, display up to N recorded logs')

#    logs_deploy.add_argument('--from', metavar='DATE',
#            help='Start from DATE. DATE Can be XXX define format XXX'
#            ' or a negative value from now (ex: -1h)')
#    logs_deploy.add_argument('--to', metavar='DATE',
#            help='End at DATE. Same format as --from.'
#            ' If --no-follow, display up to DATE'
#            )

    logs_app = logs.add_parser('app', help='Watch your application in live',
            parents=[common_parser])

    service_or_instance = logs_app.add_mutually_exclusive_group()
    service_or_instance.add_argument('service', nargs='?',
            help='Filter logs upon a given service (ex: www).')
    service_or_instance.add_argument('instance', nargs='?',
            help='Filter logs upon a given service instance (ex: www.0).')

    logs_app.add_argument('--no-follow', '-N', action='store_true',
            help='Do not follow real-time logs')
    logs_app.add_argument('--lines', '-n', type=int, metavar='N',
            help='Tail only N logs (before following real-time logs by default)')


    def validate_var(kv):
        if kv.count('=') != 1:
            raise argparse.ArgumentTypeError('You must assign a value ' \
                    'to "{0}" (e.g. {0}=VALUE)'.format(kv, kv))
        (k, v) = kv.split('=')
        if not v:
            raise argparse.ArgumentTypeError('Invalid value for "{0}": '\
                    'Values cannot be empty'.format(k))
        return kv

    var = subcmd.add_parser('var', help='Manipulate application variables',
            parents=[common_parser]).add_subparsers(dest='subcmd')
    var_list = var.add_parser('list', help='List the application variables',
            parents=[common_parser])
    var_set = var.add_parser('set', help='Set new application variables',
            parents=[common_parser])
    var_set.add_argument('values', help='Application variables to set',
                         metavar='key=value', nargs='+', type=validate_var)
    var_unset = var.add_parser('unset', help='Unset application variables',
            parents=[common_parser])
    var_unset.add_argument('variables', help='Application variables to unset', metavar='var', nargs='+')


    scale = subcmd.add_parser('scale', help='Scale services',
            description='Manage horizontal (instances) or vertical (memory) scaling of services',
            parents=[common_parser])
    scale.add_argument('services', nargs='+', metavar='service:action=value',
                       help='Scaling action to perform e.g. www:instances=2 or www:memory=1gb',
                       type=ScaleOperation)

    restart = subcmd.add_parser('restart',
            help='Restart a service\'s instance',
            parents=[common_parser])
    restart.add_argument('service_or_instance',
            help='Restart the first instance of a ' \
                    'given service (ex: www) or a specific one (ex: www.1)')

    alias = subcmd.add_parser('alias', help='Manage aliases for the service',
            parents=[common_parser]).add_subparsers(dest='subcmd')
    alias_list = alias.add_parser('list', help='List the aliases',
            parents=[common_parser])
    alias_add = alias.add_parser('add', help='Add a new alias',
            parents=[common_parser])
    alias_add.add_argument('service', help='Service to set alias for')
    alias_add.add_argument('alias', help='New alias (domain name)')
    alias_rm = alias.add_parser('rm', help='Remove an alias',
            parents=[common_parser])
    alias_rm.add_argument('service', help='Service to remove alias from')
    alias_rm.add_argument('alias', help='Alias (domain name) to remove')

    service = subcmd.add_parser('service', help='Manage services',
            parents=[common_parser]).add_subparsers(dest='subcmd')
    service_list = service.add_parser('list', help='List the services',
            parents=[common_parser])

    return parser
