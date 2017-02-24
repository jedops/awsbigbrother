import time
import csv
import boto3
import sys

try:
    import cStringIO
except ImportError:
    import io


class Client(object):
    def __init__(self, creds_report_timeout=60):
        self.client = boto3.client('iam')
        self.creds_report_timeout = creds_report_timeout

    def get_csv(self):
        if not self.poll_until_credential_report():
            raise RuntimeError('Timed out trying to get Credentials report')
        response = self.client.get_credential_report()
        return response['Content']

    def poll_until_credential_report(self):
        time_waited = 0
        while self.client.generate_credential_report() != 'COMPLETE':
            if time_waited > self.creds_report_timeout:
                return False
            time.sleep(2)
            time_waited += 2
            return True


class CSVLoader(object):
    @staticmethod
    def get_reader(csv_contents):

        if sys.version_info[0] >= 3:
            csv_file = io.StringIO()
            csv_file.write(csv_contents.decode("utf-8"))
        else:
            csv_file = cStringIO.StringIO()
            csv_file.write(csv_contents)
        csv_file.seek(0)
        reader = csv.reader(csv_file, delimiter=',')
        # We don't want the crappy title values
        next(reader)
        return reader
