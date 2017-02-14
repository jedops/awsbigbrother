from awscredsreporter.credential_report import  *
import pytest

class TestCredentialReportRow:
    def test_mfa_is_active(self):

        good_mfa_person = 'someone,arn:aws:iam::1111111111:user/someone,2016-10-24T12:49:01+00:00,' \
              'true,2016-12-22T13:26:45+00:00,2016-10-24T12:52:04+00:00,N/A,true,' \
              'true,2016-12-13T11:13:05+00:00,2016-12-13T11:19:00+00:00,eu-west-1,kms,' \
              'false,N/A,N/A,N/A,N/A,false,N/A,false,N/A'
        good_mfa_person_row_array = good_mfa_person.split(',')
        good_mfa_person_cred_row = CredentialReportRow(good_mfa_person_row_array)
        bad_mfa_person = 'someone,arn:aws:iam::1111111111:user/someone,2016-10-24T12:49:01+00:00,' \
              'true,2016-12-22T13:26:45+00:00,2016-10-24T12:52:04+00:00,N/A,false,' \
              'true,2016-12-13T11:13:05+00:00,2016-12-13T11:19:00+00:00,eu-west-1,kms,' \
              'false,N/A,N/A,N/A,N/A,false,N/A,false,N/A'
        bad_mfa_person_row_array = bad_mfa_person.split(',')
        bad_mfa_person_cred_row = CredentialReportRow(bad_mfa_person_row_array)

        assert good_mfa_person_cred_row.mfa() is None
        assert bad_mfa_person_cred_row.mfa()

class TestCheckResponse:
    def test_check_get_response(self):
        cred_check_response = CredentialCheckResponse('sausage',False,'bob').get_response()
        assert cred_check_response == "Check: sausage failed for user: bob"

class TestCredentialReportConfig:

    def test_get_timeout(self):
        cred_report_config = CredentialReportConfig()
        cred_report_config.load_from_file('fixtures/audit.conf')
        assert cred_report_config.timeout == 120

    def test_get_mfa(self):
        cred_report_config = CredentialReportConfig()
        cred_report_config.load_from_file('fixtures/audit.conf')
        assert 'mfa' in cred_report_config.actions

    def test_get_exclude_users(self):
        cred_report_config = CredentialReportConfig()
        cred_report_config.load_from_file('fixtures/audit.conf')
        assert cred_report_config.excluded_users == ['iamamoron','helpme']

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
        cred_report_action_runner = CredentialReportActionRunner(cred_report_row,config)
        assert cred_report_action_runner.password_max_age() == 'Check: password_max_age failed for user: someone'
