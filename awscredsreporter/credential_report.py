import ConfigParser
from credential_client import CredentialClient, CSVLoader
import arrow
from datetime import timedelta


class CredentialReportRow(object):
    user = "unknown"
    arn = "unknown"
    password_enabled = "unknown"
    password_last_used = "unknown"
    password_last_changed = "unknown"
    password_next_rotation = "unknown"
    mfa_active = "unknown"

    def __init__(self, row):
        self.user = row[0]
        self.arn = row[1]
        self.password_enabled = row[3]
        self.password_last_used = row[4]
        self.password_last_changed = row[5]
        self.password_next_rotation = row[6]
        self.mfa_active = row[7]

    def mfa(self):
        return CredentialCheckResponse('mfa', self.mfa_active == 'true', self.user).get_response()


class CredentialReportActionRunner(object):
    def __init__(self, row, config):
        self.__row = row
        self.__config = config

    def mfa(self):
        return CredentialCheckResponse('mfa', self.__row.mfa_active == 'true', self.__row.user).get_response()

    def password_max_age(self):
        password_stale = True
        if self.__row.password_last_changed != 'N/A':
            current_time = arrow.utcnow()
            password_last_changed = arrow.get(self.__row.password_last_changed)
            renewal_date = password_last_changed + self.__config.password_max_age
            password_stale = renewal_date > current_time
        return CredentialCheckResponse('password_max_age', password_stale, self.__row.user).get_response()


class CredentialCheckResponse(object):
    def __init__(self, check_name, check_passed, user):
        self.__check_name = check_name
        self.__check_passed = check_passed
        self.__user = user

    def get_response(self):
        if self.__check_passed == True:
            return None
        return "Check: {check_name} failed for user: {user}".format(check_name=self.__check_name,
                                                                    user=self.__user)


class CredentialReportConfig(object):
    def __init__(self):
        self.actions = []
        self.timeout = 60
        self.excluded_users = []
        self.password_max_age = timedelta(days=99999999)

    def load_from_file(self, path):
        config = ConfigParser.RawConfigParser()
        config.read(path)
        # Need to rescue here in case not defined
        self.timeout = int(config.get('global', 'timeout'))
        if config.get('global', 'mfa') == 'true':
            self.actions.append('mfa')
        self.excluded_users = config.get('global', 'excluded_users').replace(' ', '').split(',')
        self.password_max_age = timedelta(days=int(config.get('passwords', 'max_age_days')))

    def set_password_max_age(self, age):
        self.password_max_age = timedelta(days=age)
