import configparser
import arrow
from datetime import timedelta


class Config (object):

    def create_action(self, action_name):
        if action_name not in self.actions:
            self.actions.append(action_name)

    def clear(self):
        del self.actions[:]

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

class ReportConfig(Config):
    noout = False

    def __init__(self):
        self.actions = []
        self.timeout = 60
        self.excluded_users = []
        self.__access_keys_max_age = timedelta(days=99999999)
        self.__password_max_age = timedelta(days=99999999)
        self.__no_activity_max_age = timedelta(days=99999999)
        self.config = None
        self.__expected_policies = []

    @property
    def expected_policies (self):
        return self.__expected_policies

    @expected_policies.setter
    def expected_policies (self, policies):
        if policies:
            self.__expected_policies = policies.split(',')
            self.create_action('user_has_policies')

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
        self.certs_max_age = self.get_from_config('getint', 'certs', 'max_age_days')
        self.expected_policies = self.get_from_config('get', 'iam', 'expected_policies')

    @property
    def cert_1_max_age(self):
        return self.__certs_max_age

    @property
    def cert_2_max_age(self):
        return self.__certs_max_age

    @property
    def certs_max_age(self):
        return self.__certs_max_age

    @certs_max_age.setter
    def certs_max_age(self,age):
        if age:
            self.__certs_max_age = timedelta(days=age)
            self.create_action('certs_max_age')

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

    @no_activity_max_age.setter
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

