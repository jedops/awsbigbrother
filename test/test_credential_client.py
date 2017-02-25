from awsbigbrother.client import *


PY3 = (sys.version_info[0] >= 3)


class TestClient(object):
    def test_get_csv(self, vcr_test):
        with vcr_test.use_cassette('test_get_csv.yml'):
            client = Client()
            report = client.get_csv()
            if PY3:
                decoded_report = report.decode('utf-8')
                result = decoded_report.find("user,arn,user_creation_time,", 0, 28)
            else:
                result = report.find("user,arn,user_creation_time,", 0, 28)
            assert result == 0

    def test_poll_until_credential_report(self, vcr_test):
        with vcr_test.use_cassette('test_poll_until_credential_report.yml'):
            client = Client()
            assert client.poll_until_credential_report() == True


class TestCSVLoader(object):
    def test_get_reader(self, vcr_test):
        with vcr_test.use_cassette('test_get_reader.yml'):
            client = Client()
            report_csv = client.get_csv()
            csv_loader = CSVLoader()
            reader = csv_loader.get_reader(report_csv)
            for row in reader:
                assert isinstance(row[0],str)
