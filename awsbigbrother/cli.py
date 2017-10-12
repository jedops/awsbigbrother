from click import echo, command, option, style, format_filename, Path
from .report import *
from .client import CSVLoader
from .action import *
from .report import *
from .config import *

report_config = ReportConfig()


def generate_excluded_users(ctx, param, value):
    if value:
        value.replace(' ', '')
        report_config.excluded_users.extend(value.split(','))

def generate_expected_policies(ctx, param, value):
    if value:
        report_config.expected_policies = value.strip()


def parse_config_from_file(ctx, param, value):
    if value:
        echo("Using config file: {0}".format(format_filename(value)))
        report_config.load_from_file(format_filename(value))


def add_to_options(ctx, param, value):
    if value:
        setattr(report_config, param.name, value)


def noout_warning(ctx, param, value):
    if value:
        echo("noout specified - not printing check results to console")
        report_config.noout = True


@command()
@option('-c', type=Path(exists=True), callback=parse_config_from_file,
        expose_value=False, is_eager=True,
        help='Path to a security check configuration file')
@option('--mfa', is_flag=True, callback=add_to_options,
        expose_value=False, default=False,
        help='Check whether each user has Multi-factor auth setup')
@option('-e', callback=generate_excluded_users, expose_value=False, help='Users to exclude from the reporting')
@option('--expected_policies', callback=generate_expected_policies, expose_value=False, help='Check each user has a certain policy')
@option('--access_keys_max_age',
        callback=add_to_options,
        expose_value=False, type=int,
        help="The maximum age of any access keys the user has configured")
@option('--certs_max_age',
        callback=add_to_options,
        expose_value=False, type=int,
        help="The maximum age of the certs owned by a user")
@option('--password_max_age', callback=add_to_options,
        expose_value=False, type=int,
        help='The maximum age of a password in days. If the password has not been changed '
             'in this amount of days the command will report an issue')
@option('--no_activity_max_age', callback=add_to_options,
        expose_value=False, type=int,
        help='The maximum number of days of user inactivity before an error is thrown')
@option('--noout', is_flag=True, callback=noout_warning, expose_value=True,
        help="Don't print out the check results to the console (e.g. if you run this on a public service)")
def app(noout):
    """AWS Credentials reporter.
       This command checks your AWS account users for security issues.
       Options can either be specified as command line arguments or in a configuration file. The order of precedence is as follows:

       1. Command line arguments

       2. Configuration files

       3. Default values
    """
    problems = False
    credential_client = Client()
    report_csv = credential_client.get_csv()
    csv_loader = CSVLoader()
    reader = csv_loader.get_reader(report_csv)
    for row in reader:
        report_row = ReportRow(row)
        if report_row.user in report_config.excluded_users:
            continue
        action_runner = ReportActionRunner(report_row, report_config)
        for action in report_config.actions:
            response = getattr(action_runner, action)()
            if response:
                output(noout, response, fg='red')
                problems = True
    if problems:
        echo("Found security issues during test. Please review output.")
        # A bit sucky, but needed for the cli tests until I find a smarter way of doing things/refactor :(
        report_config.clear()
        exit(1)
    output(noout, "No security issues found", fg='green')
    report_config.clear()


def output(noout, text, fg=None):
    if not report_config.noout:
        echo(style(text, fg=fg))
