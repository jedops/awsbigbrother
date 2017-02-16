from awsbigbrother.credential_report import *
import pytest


class TestCredentialReportRow:
    mfa_string = 'fakeuser6,arn:aws:iam::123456789123:user/fakeuser6,2015-12-15T12:43:05+00:00,' \
                 'false,N/A,N/A,N/A,{0},true,2015-12-15T12:55:15+00:00,2015-12-15T15:14:00+00:00,' \
                 'eu-west-1,ec2,true,2015-12-15T12:55:15+00:00,2015-12-15T15:14:00+00:00,' \
                 'eu-west-1,ec2,false,N/A,false,N/A'

    @pytest.mark.parametrize("input,expected", [
        (mfa_string.format('true'), None),
        (mfa_string.format('false'), 'Check: mfa failed for user: fakeuser6'),
    ])
    def test_mfa_active(self,input,expected):

        cred_row = CredentialReportRow(input.split(','))
        assert cred_row.mfa() == expected

class TestCheckResponse:
    def test_check_get_response(self):
        cred_check_response = CredentialCheckResponse('sausage', False, 'bob').get_response()
        assert cred_check_response == "Check: sausage failed for user: bob"


class TestCredentialReportConfig:

    @pytest.fixture
    def cred_report_config(self):
        cred_report_config = CredentialReportConfig()
        cred_report_config.load_from_file('fixtures/audit.conf')
        return cred_report_config

    def test_cred_report_config(self, cred_report_config ):
        assert cred_report_config.timeout == 120
        assert 'mfa' in cred_report_config.actions
        assert cred_report_config.excluded_users == ['iamamoron', 'helpme']

class TestCredentialReportActionRunner:
    def test_password_max_age(self):
        row = 'someone,arn:aws:iam::1111111111:user/someone,2016-10-24T12:49:01+00:00,' \
              'true,2016-12-22T13:26:45+00:00,2016-10-24T12:52:04+00:00,N/A,true,' \
              'true,2016-12-13T11:13:05+00:00,2016-12-13T11:19:00+00:00,eu-west-1,kms,' \
              'false,N/A,N/A,N/A,N/A,false,N/A,false,N/A'
        row_array = row.split(',')
        cred_report_row = CredentialReportRow(row_array)
        config = CredentialReportConfig()
        config.load_from_file('fixtures/audit.conf')
        cred_report_action_runner = CredentialReportActionRunner(cred_report_row, config)
        assert cred_report_action_runner.password_max_age() == 'Check: password_max_age failed for user: someone'

    def test_password_max_age_passes(self):
        row = 'someone,arn:aws:iam::1111111111:user/someone,2017-10-24T12:49:01+00:00,' \
              'true,2017-12-22T13:26:45+00:00,2017-10-24T12:52:04+00:00,N/A,true,' \
              'true,2017-12-13T11:13:05+00:00,2017-12-13T11:19:00+00:00,eu-west-1,kms,' \
              'false,N/A,N/A,N/A,N/A,false,N/A,false,N/A'
        row_array = row.split(',')
        cred_report_row = CredentialReportRow(row_array)
        config = CredentialReportConfig()
        config.load_from_file('fixtures/audit.conf')
        cred_report_action_runner = CredentialReportActionRunner(cred_report_row, config)
        assert not cred_report_action_runner.password_max_age()

    def test_access_key_max_age(self):
        row = 'fakeuser6,arn:aws:iam::123456789123:user/fakeuser6,2015-12-15T12:43:05+00:00,' \
              'false,N/A,N/A,N/A,false,true,2015-12-15T12:55:15+00:00,2015-12-15T15:14:00+00:00,' \
              'eu-west-1,ec2,true,2015-12-15T12:55:15+00:00,2015-12-15T15:14:00+00:00,' \
              'eu-west-1,ec2,false,N/A,false,N/A'
        row_array = row.split(',')
        cred_report_row = CredentialReportRow(row_array)
        config = CredentialReportConfig()
        config.load_from_file('fixtures/audit.conf')
