from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / "tests" / "test.apk"

g = GlorifiedAndroid(test_apk.resolve(), output_dir="/tmp/ggtest")


def test_other_ad_networks():
    assert g.other_ad_networks().count == 1


def test_other_all_urls():
    assert g.other_all_urls().count == 1


def test_other_aws_keys():
    assert g.other_aws_keys().count == 0


def test_other_unicode_chars():
    assert g.other_unicode_chars("Han").count > 100


def test_other_content_urlhandler():
    assert g.other_content_urlhandler().count == 0


def test_other_email_addresses():
    assert g.other_email_addresses().count == 0


def test_other_file_urlhandler():
    assert g.other_file_urlhandler().count == 0


def test_other_find_trackers_ads():
    assert len(g.other_find_trackers_ads()) == 0


def test_other_github_token():
    assert g.other_github_token().count == 0


def test_other_google_ads_import():
    assert g.other_google_ads_import().count == 0


def test_other_http_urls():
    assert g.other_http_urls().count == 1


def test_other_ip_address():
    assert g.other_ip_address().count == 0


def test_other_password_in_url():
    assert g.other_password_in_url().count == 0


def test_other_secret_keys():
    assert g.other_secret_keys().count == 0


def test_other_websocket_urlhandler():
    assert g.other_websocket_urlhandler().count == 0
