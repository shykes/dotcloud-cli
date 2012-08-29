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

        if self.action == 'instances':
            try:
                self.original_value = int(v)
                self.value = int(v)
            except ValueError:
                raise argparse.ArgumentTypeError('Invalid value for "{0}": ' \
                        'Instance count must be a number'.format(kv))
        elif self.action == 'memory':
            self.original_value = v
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

    common_parser = Parser(prog=name, add_help=False)
    common_parser.add_argument('--application', '-A', help='specify the application')

    connect_options_parser = Parser(prog=name, add_help=False)
    rsync_or_dvcs = connect_options_parser.add_mutually_exclusive_group()
    rsync_or_dvcs.add_argument('--rsync', '-a', action='store_true',
            help='Always use rsync to push (default)')
    rsync_or_dvcs.add_argument('--git', '-g', action='store_true',
            help='Always use git to push')
    rsync_or_dvcs.add_argument('--hg', '-m', action='store_true',
            help='Always use mercurial to push')

    branch_or_commit = connect_options_parser.add_mutually_exclusive_group()
    branch_or_commit.add_argument('--branch', '-b', metavar='NAME',
            help='Always use this branch when pushing via dvcs (by default, use the active one)')

    parser = Parser(prog=name, description='dotcloud CLI',
            parents=[common_parser])
    parser.add_argument('--version', '-v', action='version', version='dotcloud/{0}'.format(VERSION))

    subcmd = parser.add_subparsers(dest='cmd')

    subcmd.add_parser('list', help='list applications')

    check = subcmd.add_parser('check', help='Check that the client is properly setup')
    setup = subcmd.add_parser('setup', help='Setup the client authentication')

    create = subcmd.add_parser('create', help='Create a new application',
            parents=[connect_options_parser])
    create.add_argument('--flavor', '-f', default='sandbox',
            help='Choose a flavor for your application. Defaults to sandbox.')
    create.add_argument('application', help='specify the application')

    conn = subcmd.add_parser('connect', help='Connect the current directory with an existing application',
            parents=[connect_options_parser])
    conn.add_argument('application', help='specify the application')

    destroy = subcmd.add_parser('destroy', help='Destroy an application',
            parents=[common_parser])
    destroy.add_argument('service', nargs='?', help='Optionally, only destroy the specified service')

    disconnect = subcmd.add_parser('disconnect', help='Disconnect the current directory')

    app = subcmd.add_parser('app', help='Show the application connected to the current directory')

    activity = subcmd.add_parser('activity', help='List recent activity',
            parents=[common_parser])

    activity.add_argument('--all' ,'-a', action='store_true',
            help='Print out your activities among all your applications'
            ' rather than the currently connected or selected one.'
            ' Implicit when not connected to any application')

    info = subcmd.add_parser('info', help='Get information about the application',
            parents=[common_parser])
    info.add_argument('service', nargs='?', help='Optionally select a single service in the application')

    url = subcmd.add_parser('url', help='Show URL for the application',
            parents=[common_parser])
    url.add_argument('service', nargs='?', help='Specify the service')

    open_ = subcmd.add_parser('open', help='Open the application in a browser',
            parents=[common_parser])
    open_.add_argument('service', nargs='?', help='Specify the service')

    run = subcmd.add_parser('run',
            help='Open a shell or run a command inside a container',
            parents=[common_parser])
    run.add_argument('service_or_instance',
            metavar='SERVICE[.CONTAINER]'
            help='Select the container in which to run the command, by service name and container id (eg: www.1). ' \
                    'If CONTAINER is omitted, the first container in the service will be selected (eg: www)'
                )
    run.add_argument('command', nargs='?',
            help='The command to run. If not specified, open a shell.')
    run.add_argument('args', nargs=argparse.REMAINDER, metavar='...',
            help='Any arguments to the command')

    push = subcmd.add_parser('push', help='Upload code from the current directory and deploy it to the application',
            parents=[common_parser])
    push.add_argument('path', nargs='?', default=None,
            help='Path to the local directory to upload (default "./")')
    push.add_argument('--clean', action='store_true',
            help='Perform a clean build rather than incremental')

    rsync_or_dvcs = push.add_mutually_exclusive_group()
    rsync_or_dvcs.add_argument('--rsync', '-a', action='store_true',
            help='Upload with rsync (default)')
    rsync_or_dvcs.add_argument('--git', '-g', action='store_true',
            help='Upload with "git push"')
    rsync_or_dvcs.add_argument('--hg', '-m', action='store_true',
            help='Upload with "hg push")

    branch_or_commit = push.add_mutually_exclusive_group()
    branch_or_commit.add_argument('--branch', '-b', metavar='NAME',
            help='Specify the branch to push when pushing via dvcs (by default, use the active one)')
    branch_or_commit.add_argument('--commit', '-c', metavar='HASH',
            help='Specify the commit hash to push when pushing via dvcs (by default, use the latest one)')

    deploy = subcmd.add_parser('deploy', help='Deploy a new version of the application',
            parents=[common_parser])
    deploy.add_argument('revision',
            metavar='REVISION|"latest"|"previous"',
            help='Revision to deploy')
    deploy.add_argument('--clean', action='store_true',
            help='Perform a clean build if a build is needed')

    dlist = subcmd.add_parser('dlist', help='List recents deployments',
            parents=[common_parser])

    dlogs = subcmd.add_parser('dlogs', help='Audit deployment logs',
            parents=[common_parser])

    dlogs.add_argument('d', metavar='DEPLOYMENT | "latest"',
            help='Select a deployment to audit (SEE ALSO: dlist)'
        )

    service_or_instance = dlogs.add_mutually_exclusive_group()
    service_or_instance.add_argument('service', nargs='?',
            metavar='SERVICE',
            help='Only display logs produced by service SERVICE (eg. www)'
            )
    service_or_instance.add_argument('instance', nargs='?',
            metavar='CONTAINER'
            help='Filter logs upon a given service instance (ex: www.0).'
            ' Can be refined further with --build or --install')

    dlogs.add_argument('--no-follow', '-N', action='store_true',
            help='Do not follow real-time logs')
    dlogs.add_argument('--lines', '-n', type=int, metavar='N',
            help='Tail only N logs (before following real-time logs by default)')

#    dlogs.add_argument('--build', action='store_true',
#            help='Retrieve only build logs.')
#    dlogs.add_argument('--install', action='store_true',
#            help='Retrieve only install logs.')

#    dlogs.add_argument('--head', '-H', type=int, metavar='N',
#            help='Display the first N logs.'
#            ' Wait after real-time logs if needed.'
#            ' If --no-follow, display up to N recorded logs')

#    dlogs.add_argument('--from', metavar='DATE',
#            help='Start from DATE. DATE Can be XXX define format XXX'
#            ' or a negative value from now (ex: -1h)')
#    dlogs.add_argument('--to', metavar='DATE',
#            help='End at DATE. Same format as --from.'
#            ' If --no-follow, display up to DATE'
#            )

    logs = subcmd.add_parser('logs', help='Watch your application logs live',
            parents=[common_parser])


    logs.add_argument('service_or_instance',
            metavar='SERVICE[.CONTAINER]',
            help='Filter logs by source: select a single source container (eg: "www.0") or select an entire service (eg: "www")'
        )

    logs.add_argument('--no-follow', '-N', action='store_true',
            help='Do not follow real-time logs')
    logs.add_argument('--lines', '-n', type=int, metavar='N',
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
            help='Restart a service instance',
            parents=[common_parser])
    restart.add_argument('service_or_instance',
            help='Restart the first instance of a ' \
                    'given service (ex: www) or a specific one (ex: www.1)')

    domain = subcmd.add_parser('domain', help='Manage domains for the service',
            parents=[common_parser]).add_subparsers(dest='subcmd')
    domain_list = domain.add_parser('list', help='List the domains',
            parents=[common_parser])
    domain_add = domain.add_parser('add', help='Add a new domain',
            parents=[common_parser])
    domain_add.add_argument('service', help='Service to set domain for')
    domain_add.add_argument('domain', help='New domain name')
    domain_rm = domain.add_parser('rm', help='Remove a domain',
            parents=[common_parser])
    domain_rm.add_argument('service', help='Service to remove the domain from')
    domain_rm.add_argument('domain', help='domain name to remove')

    service = subcmd.add_parser('service', help='Manage services',
            parents=[common_parser]).add_subparsers(dest='subcmd')
    service_list = service.add_parser('list', help='List the services',
            parents=[common_parser])

    revisions = subcmd.add_parser('revisions',
            help='Display all the knowns revision of the application',
            parents=[common_parser])

    return parser
