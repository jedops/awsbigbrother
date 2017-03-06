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
        self.user_creation_time = row[2]
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
        password_older_than_max_age = self.check_no_rotation_since_days(self.config.password_max_age, ['password'])
        return CheckResponse('password_max_age', not password_older_than_max_age,
                             self.row.user).get_response()

    def access_keys_max_age(self):
        check_list = ['access_key_1', 'access_key_2']
        if self.check_no_rotation_since_days(self.config.access_keys_max_age, check_list):
            return CheckResponse("access_key_max_age", False, self.row.user).get_response()

    def check_no_rotation_since_days(self, max_age, check_list):
        row = self.row
        for attribute_name in check_list:
            # This could be refactored
            if self.row_active(row, attribute_name):
                timestamp = getattr(row, "{0}_last_rotated".format(attribute_name))
                if self.is_used(timestamp):
                    return self.is_older_than_days(timestamp, max_age)
        return False

    @classmethod
    def row_active(cls, row, attribute_name):
        row_is_active = getattr(row, "{0}_active".format(attribute_name))
        return cls.is_used(row_is_active)

    @classmethod
    def is_used(cls, attribute):
        return not (attribute == 'false' or attribute == 'N/A' or attribute == 'not_supported')

    def no_activity_max_age(self):
        row = self.row
        attr_list = ['password', 'access_key_1', 'access_key_2']
        no_activity = False
        for attr in attr_list:
            if self.row_active(row, attr):
                attr_last_used = getattr(row, "{0}_last_used".format(attr))
                if attr_last_used == 'no_information':
                    attr_last_used = row.user_creation_time
                max_age = self.config.no_activity_max_age
                if self.is_older_than_days(attr_last_used, max_age):
                    no_activity = True
        return CheckResponse('no_activity_max_age', not no_activity,
                             self.row.user).get_response()

    @classmethod
    def is_older_than_days(cls, timestamp, max_age):
        if not cls.is_used(timestamp):
            return False
        current_time = arrow.utcnow()
        try:
            utc_timestamp = arrow.get(timestamp)
        except arrow.parser.ParserError:
            print("failed to parse {0} as a time format. You've found a bug:".format(timestamp))
            print("Please report it here: https://github.com/jae2/awsbigbrother/issues".format(timestamp))
            raise
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
        self.__no_activity_max_age = timedelta(days=99999999)
        self.config = None

    def load_from_file(self, path):

        self.config = configparser.RawConfigParser(allow_no_value=True)
        self.config.read(path)
        self.timeout = self.get_from_config('getint','global', 'timeout') or 60
        if self.config.get('global', 'mfa') == 'true':
            self.actions.append('mfa')
        self.excluded_users = self.get_from_config('get', 'global', 'excluded_users').replace(' ', '').split(',') or []
        self.password_max_age = self.get_from_config('getint', 'passwords', 'max_age_days')
        self.access_keys_max_age = self.get_from_config('getint', 'access_keys', 'max_age_days')
        self.no_activity_max_age = self.get_from_config('getint', 'global', 'no_activity_max_age')

    def get_from_config(self, method, section, key):
        try:
            method = getattr(self.config, method)
            value = method(section, key)
        except configparser.NoSectionError:
            value = None
        except configparser.NoOptionError:
            value = None
        if value:
            return value
        return None

    @property
    def access_key_1_max_age(self):
        return self.__access_keys_max_age

    @property
    def access_key_2_max_age(self):
        return self.__access_keys_max_age

    @property
    def access_keys_max_age(self):
        return self.__access_keys_max_age

    @access_keys_max_age.setter
    def access_keys_max_age(self, age):
        if age:
            self.__access_keys_max_age = timedelta(days=age)
            self.create_action('access_keys_max_age')

    @property
    def no_activity_max_age(self):
        return self.__no_activity_max_age

    @access_keys_max_age.setter
    def no_activity_max_age(self, age):
        if age:
            self.__no_activity_max_age = timedelta(days=age)
            self.create_action('no_activity_max_age')

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
        if age:
            self.__password_max_age = timedelta(days=age)
            self.create_action('password_max_age')

    def create_action(self, action_name):
        if action_name not in self.actions:
            self.actions.append(action_name)

    def clear(self):
        del self.actions[:]
