import json

import pytest

from benchmarks.injecagent_adapter import (
    InjecAgentSchemaError,
    _self_test_example,
    load_injecagent_fixtures,
    map_record_to_fixture,
)


def test_synthetic_example_maps_correctly():
    record = _self_test_example()
    fixture = map_record_to_fixture(record, index=0)
    assert fixture.is_malicious is True
    assert fixture.destination_allowed is False
    assert fixture.calls[0].destination_domain == "attacker.example"
    assert "AKIA9F3KDL2839ANDX7Q" in fixture.sensitive_source


def test_benign_record_maps_correctly():
    record = _self_test_example()
    record["expected_label"] = "benign"
    record["case_id"] = "synthetic-0002"
    fixture = map_record_to_fixture(record, index=1)
    assert fixture.is_malicious is False
    assert fixture.destination_allowed is True
    assert fixture.sensitive_source is None


def test_missing_required_field_raises():
    record = _self_test_example()
    del record["tool_response_content"]
    with pytest.raises(InjecAgentSchemaError):
        map_record_to_fixture(record, index=0)


def test_invalid_label_raises():
    record = _self_test_example()
    record["expected_label"] = "not_a_real_label"
    with pytest.raises(InjecAgentSchemaError):
        map_record_to_fixture(record, index=0)


def test_load_from_file(tmp_path):
    records = [_self_test_example()]
    path = tmp_path / "injecagent_sample.json"
    path.write_text(json.dumps(records))

    fixtures = load_injecagent_fixtures(path)
    assert len(fixtures) == 1
    assert fixtures[0].category == "INJECAGENT-M"


def test_load_rejects_non_list_top_level(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"not": "a list"}))
    with pytest.raises(InjecAgentSchemaError):
        load_injecagent_fixtures(path)


def test_sink_without_url_yields_no_domain():
    record = _self_test_example()
    record["sink"] = {"tool_name": "write_file", "url": None, "path": "/tmp/out.txt"}
    fixture = map_record_to_fixture(record, index=0)
    assert fixture.calls[0].destination_domain is None
