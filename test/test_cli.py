import click
from click.testing import CliRunner
from awscredsreporter.cli import *
from click import option
import pytest

def test_mfa(vcr_test):

    with vcr_test.use_cassette('mfa_cli_test.yml'):
        runner = CliRunner()
        result = runner.invoke(app, ['--mfa'])
        assert "mfa failed for user" in result.output


def test_config_load(vcr_test):

    with vcr_test.use_cassette('config_load_test.yml'):
        runner = CliRunner()
        result = runner.invoke(app, ['-c', 'fixtures/audit.conf'])
        assert "mfa failed for user" in result.output

def test_without_mfa(vcr_test):

    with vcr_test.use_cassette('config_load_test.yml'):
        runner = CliRunner()
        result = runner.invoke(app, ['-c', 'fixtures/audit_mfa_off.conf'])
        assert "mfa failed for user" not in result.output

def test_password_max_age(vcr_test):

    with vcr_test.use_cassette('password_max_age_check.yml'):
        runner = CliRunner()
        result = runner.invoke(app, ['--password_max_age', '30'])
        assert "password_max_age failed for user" in result.output
