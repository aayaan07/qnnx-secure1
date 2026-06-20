import pytest
from proxy.socks5 import do_handshake, read_request, send_success, send_failure


class MockReader:
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def read(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


class MockWriter:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data: bytes):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_handshake_no_auth():
    # Browser: version=5, 1 method, no-auth(0x00)
    reader = MockReader(bytes([0x05, 0x01, 0x00]))
    writer = MockWriter()
    await do_handshake(reader, writer)
    assert writer.data == bytes([0x05, 0x00])


@pytest.mark.asyncio
async def test_handshake_bad_version_raises():
    reader = MockReader(bytes([0x04, 0x01, 0x00]))
    writer = MockWriter()
    with pytest.raises(ValueError, match="Unsupported SOCKS version"):
        await do_handshake(reader, writer)


@pytest.mark.asyncio
async def test_read_request_ipv4():
    # CONNECT 1.2.3.4:80
    data = bytes([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50])
    reader = MockReader(data)
    host, port = await read_request(reader)
    assert host == "1.2.3.4"
    assert port == 80


@pytest.mark.asyncio
async def test_read_request_domain():
    # CONNECT example.com:443
    domain = b"example.com"
    data = (
        bytes([0x05, 0x01, 0x00, 0x03, len(domain)])
        + domain
        + bytes([0x01, 0xBB])
    )
    reader = MockReader(data)
    host, port = await read_request(reader)
    assert host == "example.com"
    assert port == 443


@pytest.mark.asyncio
async def test_read_request_ipv6():
    # CONNECT ::1:80
    ipv6_bytes = bytes(15) + bytes([1])  # ::1
    data = bytes([0x05, 0x01, 0x00, 0x04]) + ipv6_bytes + bytes([0x00, 0x50])
    reader = MockReader(data)
    host, port = await read_request(reader)
    assert ":" in host  # IPv6 address contains colons
    assert port == 80


@pytest.mark.asyncio
async def test_send_success_bytes():
    writer = MockWriter()
    await send_success(writer)
    assert writer.data[0] == 0x05  # SOCKS5
    assert writer.data[1] == 0x00  # success (REP)
    assert len(writer.data) == 10  # VER REP RSV ATYP + 4-byte addr + 2-byte port


@pytest.mark.asyncio
async def test_send_failure_bytes():
    writer = MockWriter()
    await send_failure(writer)
    assert writer.data[0] == 0x05  # SOCKS5
    assert writer.data[1] == 0x01  # general failure (REP)
    assert len(writer.data) == 10
