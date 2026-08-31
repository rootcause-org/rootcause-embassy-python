from rootcause_embassy.action import _CappedStringIO


def test_stdout_cap_counts_utf8_bytes_without_splitting_characters() -> None:
    output = _CappedStringIO(4)
    assert output.write("ééé") == 3
    assert output.getvalue() == "éé"
    assert len(output.getvalue().encode()) == 4
