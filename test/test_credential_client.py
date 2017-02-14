from awscredsreporter.credential_client import *
import pytest


class TestCredentialClient:
    def test_get_csv(self, vcr_test):
        with vcr_test.use_cassette('test_get_csv.yml'):
            credential_client = CredentialClient()
            report = credential_client.get_csv()
            assert 0 == report.find("user,arn,user_creation_time,", 0, 28)

    def test_poll_until_credential_report(self, vcr_test):
        with vcr_test.use_cassette('test_poll_until_credential_report.yml'):
            credential_client = CredentialClient()
            assert credential_client.poll_until_credential_report() == True


class TestCSVLoader:
    def test_get_reader(self, vcr_test):
        with vcr_test.use_cassette('test_get_reader.yml'):
            credential_client = CredentialClient()
            report_csv = credential_client.get_csv()
            csv_loader = CSVLoader()
            reader = csv_loader.get_reader(report_csv)
            for row in reader:
                assert type(row[0]) is str
