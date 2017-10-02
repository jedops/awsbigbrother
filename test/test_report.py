from awsbigbrother.report import *
from awsbigbrother.action import ReportActionRunner
from awsbigbrother.config import ReportConfig
from datetime import timedelta
import pytest


class TestReportRow(object):
    mfa_string = 'fakeuser6,arn:aws:iam::123456789123:user/fakeuser6,2015-12-15T12:43:05+00:00,' \
                 'true,N/A,N/A,N/A,{0},true,2015-12-15T12:55:15+00:00,2015-12-15T15:14:00+00:00,' \
                 'eu-west-1,ec2,true,2015-12-15T12:55:15+00:00,2015-12-15T15:14:00+00:00,' \
                 'eu-west-1,ec2,false,N/A,false,N/A'

    @pytest.mark.parametrize("input,expected", [
        (mfa_string.format('true'), None),
        (mfa_string.format('false'), 'Check: mfa failed for user: fakeuser6'),
    ])
    def test_mfa_active(self, input, expected):
        cred_row = ReportRow(input.split(','))
        assert cred_row.mfa() == expected

class TestCheckResponse(object):
    def test_check_get_response(self):
        cred_check_response = CheckResponse('sausage', False).check_failed_for_user('bob')
        assert cred_check_response == "Check: sausage failed for user: bob"

    def test_policy_not_found_in_group_response (self):
        policy_check_response= CheckResponse('sausage', False).check_policy_not_present_for_user('policy', 'user')
        assert policy_check_response == "Policy: policy not present for user user"


class TestReportConfig(object):
    @pytest.fixture
    def cred_report_config(self):
        cred_report_config = ReportConfig()
        cred_report_config.load_from_file('fixtures/audit.conf')
        return cred_report_config

    def test_cred_report_config(self, cred_report_config):
        assert cred_report_config.timeout == 120
        assert 'mfa' in cred_report_config.actions
        assert cred_report_config.excluded_users == ['iamamoron', 'helpme']



#TODO: Refactor into test_action.py
class TestReportActionRunner(object):

    # Need to get better test data!
    row = "{1},arn:aws:iam::123456789123:user/{1},{0}-12-15T12:43:05+00:00," \
          "true,{0}-12-15T12:55:15+00:00,{0}-12-15T12:55:15+00:00,N/A,false," \
          "true,{0}-12-15T12:55:15+00:00,{0}-12-15T15:14:00+00:00," \
          "eu-west-1,ec2,true,{0}-12-15T12:55:15+00:00,{0}-12-15T15:14:00+00:00," \
          "eu-west-1,ec2,true,{0}-12-15T15:14:00+00:00,true,{0}-12-15T15:14:00+00:00"

    @pytest.fixture()
    def action_runner(self, request):
        def get_action_runner(year, user='fakeuser6'):
            row_array = self.row.format(year, user).split(',')
            cred_report_row = ReportRow(row_array)
            config = ReportConfig()
            config.load_from_file('fixtures/audit.conf')
            return ReportActionRunner(cred_report_row, config)
        return get_action_runner

    def test_password_max_age(self, action_runner):
        action_runner = action_runner('2016')
        assert 'Check: password_max_age failed for user: fakeuser6' in action_runner.password_max_age()

    def test_password_max_age_in_range(self, action_runner):
        action_runner = action_runner('2019')
        assert not action_runner.password_max_age()

    def test_access_keys_max_age(self,action_runner):
        action_runner_ = action_runner('2016')
        assert 'Check: access_key_max_age failed for user: fakeuser6' in action_runner_.access_keys_max_age()

    def test_certs_max_age(self,action_runner):
        action_runner_ = action_runner('2016')
        assert 'Check: certs_max_age failed for user: fakeuser6' in action_runner_.certs_max_age()

    def test_row_active(self):
        row_array = self.row.format('2016','fakeuser6').split(',')
        cred_report_row = ReportRow(row_array)
        active = ReportActionRunner.attribute_active_for_row(cred_report_row, 'password')
        assert active

    def test_check_no_rotation_since_days(self, action_runner):
        action_runner = action_runner('2016')
        rotation_since_days = action_runner.check_no_rotation_since_days(timedelta(days=30),
                                                          ['access_key_1', 'access_key_2', 'password'])
        assert rotation_since_days

    def test_no_activity_max_age(self, action_runner):
        action_runner = action_runner('2016')
        activity_since_days = action_runner.no_activity_max_age()
        assert activity_since_days

    def test_not_no_activity_max_age(self, action_runner):
        action_runner = action_runner('2099')
        activity_since_days = action_runner.no_activity_max_age()
        assert not activity_since_days

    def test_user_has_policies (self, action_runner, group_vcr):
        with group_vcr.use_cassette('test_user_has_policies.yml'):
            action_runner = action_runner('2009', 'awsbbuser')
            response = action_runner.user_has_policies()
            assert not response

class TestConfigLoader(object):

    def test_config_load_missing_options(self):
        reportconfig = ReportConfig()
        reportconfig.load_from_file('fixtures/audit_mfa_off.conf')
        assert isinstance(reportconfig,ReportConfig)
        assert reportconfig.timeout == 60

    def test_config_load(self):
        reportconfig = ReportConfig()
        reportconfig.load_from_file('fixtures/audit.conf')
        assert isinstance(reportconfig, ReportConfig)
        assert reportconfig.timeout == 120

