from rootcause_embassy.result import decode_result


def test_present_empty_decline_is_still_a_decline() -> None:
    result = decode_result({"analysis_id": "run", "decline": {}})
    assert result.decline is not None
    assert not result.ok
