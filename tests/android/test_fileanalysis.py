from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / "tests" / "test.apk"

g = GlorifiedAndroid(test_apk.resolve(), output_dir="/tmp/ggtest")


def test_file_activities_handling_passwords():
    assert len(g.file_activities_handling_passwords()) == 0


def test_file_database_file_paths():
    assert g.file_database_file_paths() == None


# def test_file_get_file_types():
#     assert len(g.file_get_file_types()) == 5


def test_file_get_java_classes():
    assert len(g.file_get_java_classes()) == 563


def test_file_hash_of_apk():
    assert len(g.file_hash_of_apk()) == 3


def test_file_html_files():
    assert len(g.file_html_files()) == 0


def test_file_interesting():
    assert len(g.file_interesting()) == 0


def test_file_jar_files():
    assert len(g.file_jar_files()) == 0


def test_file_js_files():
    assert len(g.file_js_files()) == 0


def test_file_kivy_app():
    assert g.file_kivy_app() == False


def test_file_native_code():
    assert len(g.file_native_code()) == 4


def test_file_other_langs():
    assert len(g.file_other_langs()) == 2


def test_file_react_app():
    assert g.file_react_app() == False


def test_file_res_strings():
    assert len(g.file_res_strings()) == 0


def test_file_resource_xml():
    assert len(g.file_resource_xml()) == 0


def test_file_shared_libs_file_paths():
    assert len(g.file_shared_libs_file_paths()) == 4


def test_file_xml_files():
    assert len(g.file_xml_files()) == 274
