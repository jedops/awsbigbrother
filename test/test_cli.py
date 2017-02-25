import pytest
from awsbigbrother.cli import app
from click.testing import CliRunner


class TestCli(object):

    @pytest.fixture
    def my_runner(self):
        runner = CliRunner()
        yield runner
        runner = None

    def test_mfa(self, vcr_test, my_runner):
        with vcr_test.use_cassette('mfa_cli_test.yml'):
            result = my_runner.invoke(app, ['--mfa'])
            assert "mfa failed for user" in result.output

    def test_config_load(self, vcr_test):
        with vcr_test.use_cassette('config_load_test.yml'):
            runner = CliRunner()
            result = runner.invoke(app, ['-c', 'fixtures/audit.conf'])
            assert "mfa failed for user" in result.output
            assert "password_max_age failed for user" in result.output
            assert "access_key_max_age failed for user" in result.output

    def test_without_mfa(self, vcr_test):
        with vcr_test.use_cassette('config_load_test.yml'):
            runner = CliRunner()
            result = runner.invoke(app, ['-c', 'fixtures/audit_mfa_off.conf'])
            assert "mfa failed" not in result.output

    def test_password_max_age(self, vcr_test, my_runner):
        with vcr_test.use_cassette('password_max_age_check.yml'):
            result = my_runner.invoke(app, ['--password_max_age', 30])
            assert "password_max_age failed for user" in result.output

    def test_password_max_age_not_mfa(self, vcr_test, my_runner):
        with vcr_test.use_cassette('password_max_age_check.yml'):
            result = my_runner.invoke(app, ['--password_max_age', '30'])
            assert "mfa failed" not in result.output

    def test_access_keys_max_age(self, vcr_test, my_runner):
        with vcr_test.use_cassette('access_keys_max_age.yml'):
            result = my_runner.invoke(app, ['--access_keys_max_age', '30'])
            assert "access_key_max_age failed for user: fakeuser1" in result.output

    def test_only_valid_options(self, vcr_test, my_runner):
        with vcr_test.use_cassette('access_keys_max_age.yml'):
            result = my_runner.invoke(app, ['--access_keys_max_age', '30'])
            assert "mfa failed" not in result.output
