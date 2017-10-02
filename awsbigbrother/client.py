import time
import csv
import boto3
from botocore.exceptions import ClientError
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

    """
    This method is supposed to obey pagination in batches of 100
    However, turns out it's kind of pointless as there's already a hard limit
    of max 100 groups in AWS anyway.
    """
    def get_all_groups(self):
        groups = self.client.list_groups()
        group_list = []
        while True:
            group_list.extend(groups.get('Groups'))
            if not groups.get('IsTruncated'):
                break
            self.client.list_groups('Marker')
        return group_list

    # list attached group policies
    # Do policy names have to be unique?
    def list_policies_for_group (self, group_name):
        # Maximum for 10 policies per group
        # Pagination seems pointless.
        response = self.client.list_attached_group_policies(GroupName=group_name)
        managed_policies = response.get('AttachedPolicies')
        all_policies = []
        if managed_policies:
            all_policies = [policy.get('PolicyName') for policy in managed_policies]
        inline_policies = self.client.list_group_policies(GroupName=group_name)
        if inline_policies:
            all_policies.extend(inline_policies['PolicyNames'])
        return all_policies

    def list_policies_for_user(self, user):
        response = self.client.list_attached_user_policies(
                UserName=user
            )
        policies = []
        for policy in response['AttachedPolicies']:
            policies.append(policy['PolicyName'])
        return policies

    def list_groups_for_user(self, user):
        response = self.client.list_groups_for_user(UserName=user)
        groups =[]
        for group in response['Groups']:
            groups.append(group['GroupName'])
        return groups

    def get_all_policies(self, user):
        policies = self.list_policies_for_user(user)
        groups = self.list_groups_for_user(user)
        for group in groups:
            policies = policies + self.list_policies_for_group(group)
        return policies


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

