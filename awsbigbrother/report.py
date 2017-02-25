import configparser
import arrow
from datetime import timedelta
from .client import Client


class ReportRow(object):
    user = "unknown"
    arn = "unknown"
    password_active = "unknown"
    password_last_used = "unknown"
    password_last_rotated = "unknown"
    password_next_rotation = "unknown"
    mfa_active = "unknown"

    def __init__(self, row):
        self.user = row[0]
        self.arn = row[1]
        self.password_active = row[3]
        self.password_last_used = row[4]
        self.password_last_rotated = row[5]
        self.password_next_rotation = row[6]
        self.mfa_active = row[7]
        self.access_key_1_active = row[8]
        self.access_key_1_last_rotated = row[9]
        self.access_key_1_last_used = row[10]
        self.access_key_2_active = row[13]
        self.access_key_2_last_rotated = row[14]
        self.access_key_2_last_used = row[15]

    def mfa(self):
        return CheckResponse('mfa', self.mfa_active == 'true', self.user).get_response()


class ActionRunner(object):
    def __init__(self, row, config):
        self.row = row
        self.config = config

    def mfa(self):
        return CheckResponse('mfa', self.row.mfa_active == 'true', self.row.user).get_response()

    def password_max_age(self):
        password_older_than_max_age = self.no_activity_max_age(self.config.password_max_age, ['password'])
        return CheckResponse('password_max_age', not password_older_than_max_age,
                             self.row.user).get_response()

    def access_keys_max_age(self):
        check_list = ['access_key_1', 'access_key_2']
        if self.no_activity_max_age(self.config.access_keys_max_age, check_list):
            return CheckResponse("access_key_max_age", False, self.row.user).get_response()

    def no_activity_max_age(self, max_age, check_list):
        row = self.row
        for attribute_name in check_list:
            row_is_active = getattr(row, "{0}_active".format(attribute_name))
            if not (row_is_active == 'false' or row_is_active == 'N/A' or row_is_active == 'not_supported'):
                timestamp = getattr(row, "{0}_last_rotated".format(attribute_name))
                return self.is_older_than_days(timestamp, max_age)
        return False

    @staticmethod
    def is_older_than_days(timestamp, max_age):
        current_time = arrow.utcnow()
        utc_timestamp = arrow.get(timestamp)
        renewal_date = utc_timestamp + max_age
        return renewal_date < current_time


class CheckResponse(object):
    def __init__(self, check_name, check_passed, user):
        self.check_name = check_name
        self.check_passed = check_passed
        self.user = user

    def get_response(self):
        if self.check_passed:
            return None
        return "Check: {check_name} failed for user: {user}".format(check_name=self.check_name,
                                                                    user=self.user)


class ReportConfig(object):
    noout = False

    def __init__(self):
        self.actions = []
        self.timeout = 60
        self.excluded_users = []
        self.__access_keys_max_age = timedelta(days=99999999)
        self.__password_max_age = timedelta(days=99999999)
        self.config = None

    def load_from_file(self, path):
        self.config = configparser.RawConfigParser()
        self.config.read(path)
        try:
            self.timeout = self.int_from_config('global', 'timeout')
        except configparser.NoOptionError:
            self.timeout = 60
        if self.config.get('global', 'mfa') == 'true':
            self.actions.append('mfa')
        self.excluded_users = self.config.get('global', 'excluded_users').replace(' ', '').split(',')
        self.password_max_age = self.int_from_config('passwords', 'max_age_days')
        self.access_keys_max_age = self.int_from_config('access_keys', 'max_age_days')

    def int_from_config(self, section, key):
        value = self.config.get(section, key)
        if value:
            return int(value)
        return None

    @property
    def access_keys_max_age(self):
        return self.__access_keys_max_age

    @access_keys_max_age.setter
    def access_keys_max_age(self, age):
        self.__access_keys_max_age = timedelta(days=age)
        self.create_action('access_keys_max_age')

    @property
    def password_max_age(self):
        return self.__password_max_age

    @property
    def mfa(self):
        return 'mfa' in self.actions

    @mfa.setter
    def mfa(self, enable):
        if enable:
            self.create_action('mfa')

    @password_max_age.setter
    def password_max_age(self, age):
        self.__password_max_age = timedelta(days=age)
        self.create_action('password_max_age')

    def create_action(self, action_name):
        if action_name not in self.actions:
            self.actions.append(action_name)

    def clear(self):
        del self.actions[:]
