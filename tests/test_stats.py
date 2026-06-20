from proxy.stats import StatsTracker


def test_record_connection_increments():
    t = StatsTracker()
    t.record_connection("example.com")
    data = t.get_all()
    assert data["example.com"]["connections"] == 1


def test_record_connection_multiple():
    t = StatsTracker()
    t.record_connection("example.com")
    t.record_connection("example.com")
    data = t.get_all()
    assert data["example.com"]["connections"] == 2


def test_record_sent_accumulates():
    t = StatsTracker()
    t.record_connection("example.com")
    t.record_sent("example.com", 100)
    t.record_sent("example.com", 250)
    data = t.get_all()
    assert data["example.com"]["bytes_sent"] == 350


def test_record_received_accumulates():
    t = StatsTracker()
    t.record_connection("example.com")
    t.record_received("example.com", 512)
    t.record_received("example.com", 512)
    data = t.get_all()
    assert data["example.com"]["bytes_received"] == 1024


def test_get_all_returns_all_hosts():
    t = StatsTracker()
    t.record_connection("a.com")
    t.record_connection("b.com")
    data = t.get_all()
    assert set(data.keys()) == {"a.com", "b.com"}


def test_get_all_structure():
    t = StatsTracker()
    t.record_connection("example.com")
    data = t.get_all()
    entry = data["example.com"]
    assert "connections" in entry
    assert "bytes_sent" in entry
    assert "bytes_received" in entry
    assert "last_seen" in entry


def test_initial_bytes_are_zero():
    t = StatsTracker()
    t.record_connection("example.com")
    data = t.get_all()
    assert data["example.com"]["bytes_sent"] == 0
    assert data["example.com"]["bytes_received"] == 0
