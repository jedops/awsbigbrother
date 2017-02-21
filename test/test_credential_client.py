from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import object
from awsbigbrother.credential_client import *

PY3 = (sys.version_info[0] >= 3)

class TestCredentialClient(object):
    def test_get_csv(self, vcr_test):
        with vcr_test.use_cassette('test_get_csv.yml'):
            credential_client = CredentialClient()
            report = credential_client.get_csv()
            if PY3:
                decoded_report = report.decode('utf-8')
                result = decoded_report.find("user,arn,user_creation_time,", 0, 28)
            else:
                result = report.find("user,arn,user_creation_time,", 0, 28)
            assert result == 0

    def test_poll_until_credential_report(self, vcr_test):
        with vcr_test.use_cassette('test_poll_until_credential_report.yml'):
            credential_client = CredentialClient()
            assert credential_client.poll_until_credential_report() == True


class TestCSVLoader(object):
    def test_get_reader(self, vcr_test):
        with vcr_test.use_cassette('test_get_reader.yml'):
            credential_client = CredentialClient()
            report_csv = credential_client.get_csv()
            csv_loader = CSVLoader()
            reader = csv_loader.get_reader(report_csv)
            for row in reader:
                assert isinstance(row[0],str)
