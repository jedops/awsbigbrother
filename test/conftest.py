import pytest
import vcr


def scrub_string(string, replacement):
    def before_record_response(response):
        if '<Content>' in response['body']['string']:
            f = open("fixtures/fake_cred_report_b64.txt", "r")
            response['body']['string'] = f.read()
            f.close
        return response

    return before_record_response


@pytest.fixture(scope="module")
def vcr_test(request):
    my_vcr = vcr.VCR(filter_headers=['authorization'],
                     cassette_library_dir='fixtures/vcr_cassettes',
                     record_mode='once',
                     before_record_response=scrub_string('', '')
                     )
    yield my_vcr
