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
        self.access_key_1_active = row[8]
        self.access_key_1_last_rotated = row[9]
        self.access_key_2_active = row[13]
        self.access_key_2_last_rotated = row[14]

    def mfa(self):
        return CredentialCheckResponse('mfa', self.mfa_active == 'true', self.user).get_response()


class CredentialReportActionRunner(object):
    def __init__(self, row, config):
        self.__row = row
        self.__config = config

    def mfa(self):
        return CredentialCheckResponse('mfa', self.__row.mfa_active == 'true', self.__row.user).get_response()

    def password_max_age(self):
        if self.__row.password_last_changed != 'N/A':
            return CredentialCheckResponse('password_max_age', self._is_expired(
                self.__row.password_last_changed,
                self.__config.password_max_age
            ),  self.__row.user).get_response()
        return None

    def access_key_max_age(self):
        if self.__row.access_key_1_active == 'true':
            problems = False
            first_check = CredentialCheckResponse('access_key_max_age', self._is_expired(
                self.__row.password_last_changed,
                self.__config.password_max_age
            ), self.__row.user).get_response()

            if self.__row.access_key_2_active == 'true':
                CredentialCheckResponse('password_max_age', self._is_expired(
                    self.__row.password_last_changed,
                    self.__config.password_max_age
                ), self.__row.user).get_response()

    def _is_expired(self, timestamp, max_age):
        current_time = arrow.utcnow()
        utc_timestamp = arrow.get(timestamp)
        renewal_date = utc_timestamp + max_age
        return renewal_date > current_time


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
