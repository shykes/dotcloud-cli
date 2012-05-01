import argparse
import sys
from .version import VERSION


class Parser(argparse.ArgumentParser):
    def error(self, message):
        print >>sys.stderr, 'error: {0}'.format(message)
        self.print_help()
        sys.exit(1)


def get_parser(name='dotcloud'):
    parser = Parser(prog=name, description='dotcloud CLI')
    parser.add_argument('--application', '-A', help='specify the application')
    parser.add_argument('--version', '-v', action='version', version='dotcloud/{0}'.format(VERSION))
    parser.add_argument('--trace', action='store_true', help='Display trace ID')

    subcmd = parser.add_subparsers(dest='cmd')

    subcmd.add_parser('list', help='list applications')

    check = subcmd.add_parser('check', help='Check the installation and authentication')
    setup = subcmd.add_parser('setup', help='Setup the client authentication')

# LOGS ---------------------------
    logs = subcmd.add_parser('logs', help='Play with logs') \
            .add_subparsers(dest='logs')

# LOGS ---------------------------

# LOGS DEPLOY --------------------
    logs_deploy = logs.add_parser('deploy', help='Play with deployments logs',
            epilog='''With no arguments it displays all the logs for the latest
            deployment. If the deployment is not yet done, then follow the
            real-time logs until completion.
            ''')

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

    logs_deploy.add_argument('--build', action='store_true',
            help='Retrieve only build logs.')
    logs_deploy.add_argument('--install', action='store_true',
            help='Retrieve only install logs.')

    logs_deploy.add_argument('--no-follow', '-n', action='store_true',
            help='Do not follow real-time logs')
    logs_deploy.add_argument('--tail', '-t', type=int, metavar='N',
            help='Tail only N logs before following real-time logs')
    logs_deploy.add_argument('--head', '-H', type=int, metavar='N',
            help='Display the first N logs.'
            ' Wait after real-time logs if needed.'
            ' If --no-follow, display up to N recorded logs')

    logs_deploy.add_argument('--from', metavar='DATE',
            help='Start from DATE. DATE Can be XXX define format XXX'
            ' or a negative value from now (ex: -1h)')
    logs_deploy.add_argument('--to', metavar='DATE',
            help='End at DATE. Same format as --from.'
            ' If --no-follow, display up to DATE'
            )

# LOGS DEPLOY --------------------

# LOGS APP -----------------------
    logs_app = logs.add_parser('app', help='Watch your application in live')

    service_or_instance = logs_app.add_mutually_exclusive_group()
    service_or_instance.add_argument('service', nargs='?',
            help='Filter logs upon a given service (ex: www).')
    service_or_instance.add_argument('instance', nargs='?',
            help='Filter logs upon a given service instance (ex: www.0).')
# LOGS APP -----------------------

    logs_history = subcmd.add_parser('history', help='Your recent activity')

    logs_history.add_argument('--all' ,'-a', action='store_true',
            help='Print out your activities among all your applications'
            ' rather than the currently connected or selected one.'
            ' Implicit when not connected to any application')

    create = subcmd.add_parser('create', help='Create a new application')
    create.add_argument('application', help='specify the application')
    create.add_argument('--repo')

    conn = subcmd.add_parser('connect', help='Connect a local directory with an existing app')
    conn.add_argument('application', help='specify the application')

    destroy = subcmd.add_parser('destroy', help='Destroy an existing app')
    destroy.add_argument('service', nargs='?', help='Specify the service')

    disconnect = subcmd.add_parser('disconnect', help='Disconnect the current directory from DotCloud app')

    app = subcmd.add_parser('app', help='Show the application name linked to the current directory')

    info = subcmd.add_parser('info', help='Get information about the application')
    info.add_argument('service', nargs='?', help='Specify the service')

    url = subcmd.add_parser('url', help='Show URL for the application')
    url.add_argument('service', nargs='?', help='Specify the service')

    ssh = subcmd.add_parser('ssh', help='SSH into the service')
    ssh.add_argument('service', help='Specify the service')

    run = subcmd.add_parser('run', help='SSH into the service')
    run.add_argument('service', help='Specify the service')
    run.add_argument('command', nargs='+', help='Run a command on the service')

    push = subcmd.add_parser('push', help='Push the code')
    push.add_argument('--clean', action='store_true', help='clean build')

    deploy = subcmd.add_parser('deploy', help='Deploy the code')
    deploy.add_argument('revision', help='Revision to deploy', default='latest', nargs='?')
    deploy.add_argument('--clean', action='store_true', help='clean build')

    def validate_var(kv):
        if kv.count('=') != 1:
            raise argparse.ArgumentTypeError('You must assign a value ' \
                    'to "{0}" (e.g. {0}=VALUE)'.format(kv, kv))
        (k, v) = kv.split('=')
        if not v:
            raise argparse.ArgumentTypeError('Invalid value for "{0}": '\
                    'Values cannot be empty'.format(k))
        return kv

    var = subcmd.add_parser('var', help='Manipulate application variables') \
        .add_subparsers(dest='subcmd')
    var_list = var.add_parser('list', help='List the application variables')
    var_set = var.add_parser('set', help='Set new application variables')
    var_set.add_argument('values', help='Application variables to set',
                         metavar='key=value', nargs='+', type=validate_var)
    var_unset = var.add_parser('unset', help='Unset application variables')
    var_unset.add_argument('variables', help='Application variables to unset', metavar='var', nargs='+')

    def validate_scaling(kv):
        if kv.count('=') != 1:
            raise argparse.ArgumentTypeError('You must specify a number ' \
                    'of instances for service "{0}" (e.g. {0}=3)'.format(kv, kv))
        (k, v) = kv.split('=')
        if not v:
            raise argparse.ArgumentTypeError('Invalid value for "{0}": '\
                    'Instance count cannot be empty'.format(k))
        try:
            v = int(v)
        except ValueError:
            raise argparse.ArgumentTypeError('Invalid value for "{0}": ' \
                    'Instance count must be a number'.format(k))
        return kv

    scale = subcmd.add_parser('scale', help='Scale services')
    scale.add_argument('services', nargs='+', metavar='service=count',
                       help='Number of instances to set for each service e.g. www=2',
                       type=validate_scaling)

    restart = subcmd.add_parser('restart', help='Restart the service')
    restart.add_argument('service', help='Specify the service')

    alias = subcmd.add_parser('alias', help='Manage aliases for the service') \
        .add_subparsers(dest='subcmd')
    alias_list = alias.add_parser('list', help='List the aliases')
    alias_add = alias.add_parser('add', help='Add a new alias')
    alias_add.add_argument('service', help='Service to set alias for')
    alias_add.add_argument('alias', help='New alias (domain name)')
    alias_rm = alias.add_parser('rm', help='Remove an alias')
    alias_rm.add_argument('service', help='Service to remove alias from')
    alias_rm.add_argument('alias', help='Alias (domain name) to remove')

    service = subcmd.add_parser('service', help='Manage services') \
        .add_subparsers(dest='subcmd')
    service_list = service.add_parser('list', help='List the services')

    return parser
