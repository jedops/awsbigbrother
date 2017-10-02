from awsbigbrother.client import *
import pytest


PY3 = (sys.version_info[0] >= 3)


class TestClient(object):

    @pytest.fixture
    def client (self):
        return Client()

    def test_get_csv(self, client, vcr_test):
        with vcr_test.use_cassette('test_get_csv.yml'):
            report = client.get_csv()
            if PY3:
                decoded_report = report.decode('utf-8')
                result = decoded_report.find("user,arn,user_creation_time,", 0, 28)
            else:
                result = report.find("user,arn,user_creation_time,", 0, 28)
            assert result == 0

    def test_poll_until_credential_report(self, client, vcr_test):
        with vcr_test.use_cassette('test_poll_until_credential_report.yml'):
            assert client.poll_until_credential_report() == True

#    def test_get_policy_list(self, vcr_test):
#        with vcr_test.use_cassette('test_get_policy_list.yml'):
#            client = Client()
#            assert client.get_policy_list() == "yep"

    def test_get_all_groups(self, client, group_vcr):
        with group_vcr.use_cassette('test_get_all_groups.yml'):
            groups = client.get_all_groups()
            for group in groups:
                assert group['GroupId'] == 'JAFFACAKES'

    def test_policies_for_group(self, client, group_vcr):
        with group_vcr.use_cassette('test_get_group_for_policy.yml'):
            policies = client.list_policies_for_group('blah')
            assert 'policygen-201611102106' in policies
            assert 'iaminline' in policies

    def test_list_policies_for_user(self, client, group_vcr):
        with group_vcr.use_cassette('list_policies_for_user.yml'):
            policies = client.list_policies_for_user('awsbbuser')
            assert 'AdministratorAccess' in policies

    def test_list_groups_for_user(self, client, group_vcr):
        with group_vcr.use_cassette('list_groups_for_user.yml'):
            groups = client.list_groups_for_user('awsbbuser')
            assert 'blah' in groups

    def test_get_all_policies (self, client, group_vcr):
        with group_vcr.use_cassette('get_all_policies.yml'):
            policies = client.get_all_policies('awsbbuser')
            assert 'policygen-201611102106' in policies
            assert 'iaminline' in policies

class TestCSVLoader(object):
    def test_get_reader(self, vcr_test):
        with vcr_test.use_cassette('test_get_reader.yml'):
            client = Client()
            report_csv = client.get_csv()
            csv_loader = CSVLoader()
            reader = csv_loader.get_reader(report_csv)
            for row in reader:
                assert isinstance(row[0],str)
