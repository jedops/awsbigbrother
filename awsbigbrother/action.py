from .report import CheckResponse
from .report import Client
import arrow
from botocore.exceptions import ClientError

class ActionRunner (object):
    pass


class ReportActionRunner(ActionRunner):
    def __init__(self, row, config):
        self.row = row
        self.config = config
        self.client = Client()

    def user_has_policies(self):
        if self.row.user == '<root_account>':
            return CheckResponse('user_has_policies', True ).check_policy_not_present_for_user('policy', self.row.user)
        try:
            policies = self.client.get_all_policies(self.row.user)
        # http://botocore.readthedocs.io/en/latest/client_upgrades.html#error-handling
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return CheckResponse('user_has_policies', False ).custom("error username not found {0}".format(self.row.user))
            raise

        for expected in self.config.expected_policies:
            if expected not in policies:
                return CheckResponse('user_has_policies', False ).check_policy_not_present_for_user(expected, self.row.user)
        return CheckResponse('user_has_policies', True ).check_policy_not_present_for_user(expected, self.row.user)

    def mfa(self):
        return CheckResponse('mfa', self.row.mfa_active == 'true').check_failed_for_user(self.row.user)

    def password_max_age(self):
        password_older_than_max_age = self.check_no_rotation_since_days(self.config.password_max_age, ['password'])
        return CheckResponse('password_max_age', not password_older_than_max_age).check_failed_for_user(self.row.user)

    def access_keys_max_age(self):
        check_list = ['access_key_1', 'access_key_2']
        if self.check_no_rotation_since_days(self.config.access_keys_max_age, check_list):
            return CheckResponse("access_key_max_age", False).check_failed_for_user(self.row.user)

    def certs_max_age(self):
        check_list = ['cert_1','cert_2']
        if self.check_no_rotation_since_days(self.config.certs_max_age, check_list):
            return CheckResponse("certs_max_age", False).check_failed_for_user(self.row.user)

    def check_no_rotation_since_days(self, max_age, check_list):
        row = self.row
        for attribute_name in check_list:
            if self.attribute_active_for_row(row, attribute_name):
                timestamp = getattr(row, "{0}_last_rotated".format(attribute_name))
                if self.is_used(timestamp):
                    return self.is_older_than_days(timestamp, max_age)
        return False

    @classmethod
    def attribute_active_for_row(cls, row, attribute_name):
        row_is_active = getattr(row, "{0}_active".format(attribute_name))
        return cls.is_used(row_is_active)

    @classmethod
    def is_used(cls, attribute):
        return not (attribute == 'false' or attribute == 'N/A' or attribute == 'not_supported')

    def no_activity_max_age(self):
        row = self.row
        attr_list = ['password','access_key_1', 'access_key_2']
        activity = False
        for attr in attr_list:
            if self.attribute_active_for_row(row, attr):
                attr_last_used  = getattr(row,"{0}_last_used".format(attr))
                if attr_last_used != 'no_information':
                    max_age = self.config.no_activity_max_age
                    if not self.is_older_than_days(attr_last_used, max_age):
                        activity = True
        return CheckResponse('no_activity_max_age', activity).check_failed_for_user(self.row.user)


    @classmethod
    def is_older_than_days(cls, timestamp, max_age):
        if not cls.is_used(timestamp):
            return False
        current_time = arrow.utcnow()
        try:
            utc_timestamp = arrow.get(timestamp)
        except arrow.parser.ParserError:
            print("failed to parse {0} as a time format. You've found a bug:".format(timestamp))
            print("Please report it here: https://github.com/jae2/awsbigbrother/issues")
            raise
        renewal_date = utc_timestamp + max_age
        return renewal_date < current_time
