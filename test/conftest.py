import pytest
import vcr
import sys

PY3 = (sys.version_info[0] >= 3)

def scrub_string(string, replacement):
    def before_record_response(response):

        if PY3:
            response['body']['string'] = response['body']['string'].decode("utf8")
        if '<Content>' in response['body']['string']:
            f = open("fixtures/fake_cred_report_b64.txt", "r")
            response['body']['string'] = f.read()
            f.close
        if PY3:
            response['body']['string'] = response['body']['string'].encode('utf-8')
        return response

    return before_record_response


@pytest.fixture(scope="module")
def vcr_test(request):

    my_vcr = vcr.VCR(filter_headers=['authorization'],
                     cassette_library_dir="fixtures/vcr_cassettes/python-{0}".format(sys.version_info[0]),
                     record_mode='once',
                     before_record_response=scrub_string('', ''),
                     decode_compressed_response=True

                     )
    yield my_vcr
