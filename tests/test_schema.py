import pytest
from normalizer.schema import normalize_event, EventValidationError

BASE = dict(timestamp_utc="2026-11-12T09:00:00+07:00",source_type="auth_log",
            src_ip="192.0.2.10",dst_ip=None,username=None,hostname=None,
            action="ssh_failed",severity="medium")

def test_normalizes_timezone_to_utc():
    assert normalize_event(BASE)["timestamp_utc"] == "2026-11-12T02:00:00.000000Z"

def test_missing_required_key_raises():
    with pytest.raises(EventValidationError, match="dst_ip"):
        normalize_event({k: v for k, v in BASE.items() if k != "dst_ip"})

def test_invalid_ip_raises():
    with pytest.raises(EventValidationError, match="src_ip"):
        normalize_event({**BASE, "src_ip": "999.9.8.7"})

def test_port_validation():
    with pytest.raises(EventValidationError, match="dst_port"):
        normalize_event({**BASE, "dst_port": 70000})
