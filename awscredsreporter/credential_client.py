import time
import cStringIO
import csv
import boto3


class CredentialClient(object):
    def __init__(self, creds_report_timeout=60):
        self.__client = boto3.client('iam')
        self.__creds_report_timeout = creds_report_timeout

    def get_csv(self):
        if not self.poll_until_credential_report():
            raise RuntimeError('Timed out trying to get Credentials report')
        response = self.__client.get_credential_report()
        return response['Content']

    def poll_until_credential_report(self):
        time_waited = 0
        while self.__client.generate_credential_report() != 'COMPLETE':
            if time_waited > self.__creds_report_timeout:
                return False
            time.sleep(2)
            time_waited += 2
            return True


class CSVLoader(object):
    @staticmethod
    def get_reader(csv_contents):
        csv_file = cStringIO.StringIO()
        csv_file.write(csv_contents)
        csv_file.seek(0)
        reader =  csv.reader(csv_file, delimiter=',')
        # We don't want the crappy title values
        reader.next()
        return reader
