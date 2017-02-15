from click import echo, command, option, style, format_filename, Path
from credential_report import *

config = CredentialReportConfig()


def add_to_actions(ctx, param, value):
    if value:
        config.actions.append(param.name)


def generate_excluded_users(ctx, param, value):
    if value:
        value.replace(' ', '')
        config.excluded_users.extend(value.split(','))


def parse_config_from_file(ctx, param, value):
    if value:
        echo("Using config file: {0}".format(format_filename(value)))
        global config
        config = CredentialReportConfig()
        config.load_from_file(format_filename(value))


def setup_password_max_age(ctx, param, value):
    if value:
        global config
        config.set_password_max_age(value)
        add_to_actions(ctx, param, value)


@command()
@option('-c', type=Path(exists=True), callback=parse_config_from_file,
        expose_value=False, is_eager=True, help='Path to a security check configuration file')
@option('--mfa', is_flag=True, callback=add_to_actions,
        expose_value=False, default=False, help='Check whether each user has Multi-factor auth setup')
@option('-e', callback=generate_excluded_users, expose_value=False, help='Users to exclude from the reporting')
@option('--password_max_age', callback=setup_password_max_age,
        expose_value=False, type=int,
        help='The maximum age of a password in days. If the password has not been changed '
             'in this amount of days the command will report an issue')
def app():
    """AWS Credentials reporter.
       This command checks your AWS account users for security issues.
       Options can either be specified as command line arguments or in a configuration file. The order of precedence is as follows:

       1) Command line arguments

       2) Configuration files

       3) Default values
    """
    problems = False
    credential_client = CredentialClient()
    report_csv = credential_client.get_csv()
    csv_loader = CSVLoader()
    reader = csv_loader.get_reader(report_csv)
    for row in reader:
        if row[0] == '<root_account>':
            continue
        cred_report_row = CredentialReportRow(row)
        if cred_report_row.user in config.excluded_users:
            continue
        cred_report_action_runner = CredentialReportActionRunner(cred_report_row, config)
        for action in config.actions:
            response = getattr(cred_report_action_runner, action)()
            if response:
                echo(style(response, fg='red'))
                problems = True

    if problems:
        echo("Found security issues during test. Please review output.")
        exit(1)
    echo(style("No security issues found", fg='green'))