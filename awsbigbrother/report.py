
from .client import Client


class ReportRow(object):

    def __init__(self, row):
        # Have chosen to use index notation here instead of
        # a,b,c = tuple because it's useful for comparing
        # value numbers against an actual report
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
        self.cert_1_active = row[18]
        self.cert_1_last_rotated = row[19]
        self.cert_2_active = row[20]
        self.cert_2_last_rotated = row[21]

    def mfa(self):
        return CheckResponse('mfa', self.mfa_active == 'true').check_failed_for_user(self.user)

class CheckResponse(object):
    def __init__(self, check_name, check_passed):
        self.check_name = check_name
        self.check_passed = check_passed
    def check_failed_for_user(self, user):
        if self.check_passed:
            return None
        return "Check: {check_name} failed for user: {user}".format(check_name=self.check_name,
                                                                    user=user)
    def check_policy_not_present_for_user(self, policy, user):
        if self.check_passed:
            return None
        return  "Policy: {policy} not present for user {user}".format(policy=policy, user=user)
    def custom (self, msg):
        return msg



