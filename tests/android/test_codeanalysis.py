from pathlib import Path

from glorifiedgrep import GlorifiedAndroid

test_dir = Path()
test_apk = test_dir / 'tests' / 'test.apk'

g = GlorifiedAndroid(test_apk.resolve())

def test_code_command_exec():
    assert g.code_command_exec().count == 0

def test_code_create_tempfile():
    assert g.code_create_tempfile().count == 0
