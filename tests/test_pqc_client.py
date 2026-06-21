import asyncio
import base64
import json
import uuid
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from client.config import HKDF_ALGORITHM, HKDF_INFO, HKDF_KEY_LENGTH, HKDF_SALT
from client.session_key import derive_session_key
from client.pqc_client import PQCClient, PQCServiceUnavailable, EncapsulationError
from client.qvpn_client import QVPNClient

# ==========================================
# 1. HKDF DERIVATION TESTS
# ==========================================

def test_hkdf_derivation_vector():
    """
    Unit test for HKDF derivation against a fixed known test vector.
    Ensures client key derivation matches the expected cryptographic output.
    """
    shared_secret = b"test_secret_key_material_value_01"
    # Pre-computed expected AES key in hex
    expected_key_hex = "d3e88c5dc22f211b9127ab121dfc43340339be923ca390de3e56446786619f85"
    
    with patch("client.session_key.HKDF_SALT", None), \
         patch("client.session_key.HKDF_INFO", b"qvpn-session-key-derivation"):
        derived_key = derive_session_key(shared_secret)
        assert derived_key.hex() == expected_key_hex


# ==========================================
# 2. PQC CLIENT WRAPPER TESTS (MOCKED HTTP)
# ==========================================

def test_pqc_client_encapsulate_success():
    """
    Verifies successful PQC API encapsulation call request shape, headers,
    and response parsing.
    """
    async def run():
        client = PQCClient(
            api_url="http://mock-api/api/v1",
            api_key="test_key",
            signing_secret="test_secret"
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "algorithm": "ML-KEM-768",
            "ciphertext": "Y2lwaGVydGV4dF9kYXRh",  # base64 of b"ciphertext_data"
            "shared_secret": "c2hhcmVkX3NlY3JldF9kYXRh",  # base64 of b"shared_secret_data"
            "status": "success"
        }
        
        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            ciphertext, shared_secret = await client.encapsulate(
                "ML-KEM-768",
                b"public_key_data"
            )
            
            assert ciphertext == b"ciphertext_data"
            assert shared_secret == b"shared_secret_data"
            
            # Verify request headers and shape
            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            
            # Check Headers
            headers = kwargs["headers"]
            assert headers["Authorization"] == "Bearer test_key"
            assert "X-QNNX-Timestamp" in headers
            assert "X-QNNX-Nonce" in headers
            assert "X-QNNX-Signature" in headers
            
            # Check Body
            body_bytes = kwargs["content"]
            body_data = json.loads(body_bytes.decode("utf-8"))
            assert body_data["algorithm"] == "ML-KEM-768"
            assert body_data["public_key"] == base64.b64encode(b"public_key_data").decode("ascii")

    asyncio.run(run())


def test_pqc_client_encapsulate_http_error():
    """
    Verifies that non-transient HTTP errors from the PQC API raise EncapsulationError.
    """
    async def run():
        client = PQCClient(api_url="http://mock-api/api/v1")
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": {"message": "Invalid Base64 for public_key"}
        }
        mock_response.text = '{"error": {"message": "Invalid Base64 for public_key"}}'
        
        with patch("httpx.AsyncClient.post", return_value=mock_response):
            with pytest.raises(EncapsulationError) as exc_info:
                await client.encapsulate("ML-KEM-768", b"pubkey")
            
            assert "Invalid Base64 for public_key" in str(exc_info.value)

    asyncio.run(run())


def test_pqc_client_encapsulate_timeout():
    """
    Verifies that transient errors/timeouts raise PQCServiceUnavailable.
    """
    async def run():
        client = PQCClient(api_url="http://mock-api/api/v1")
        
        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Connection timeout")):
            with pytest.raises(PQCServiceUnavailable) as exc_info:
                await client.encapsulate("ML-KEM-768", b"pubkey")
            
            assert "PQC API service unavailable" in str(exc_info.value)

    asyncio.run(run())


# ==========================================
# 3. HANDSHAKE INTEGRATION TEST (MOCKED PQC/GATEWAY)
# ==========================================

class MockGatewayServer:
    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port
        self.server = None
        self.derived_key = None

    async def handle_connection(self, reader, writer):
        try:
            # Read length-prefixed session_id
            len_bytes = await reader.readexactly(4)
            session_len = int.from_bytes(len_bytes, byteorder="big")
            session_id = (await reader.readexactly(session_len)).decode("utf-8")

            # Send session_id confirmation back
            writer.write(len(session_id).to_bytes(4, byteorder="big"))
            writer.write(session_id.encode("utf-8"))
            await writer.drain()

            # Read length-prefixed target JSON (but we don't need to decrypt in test)
            len_bytes = await reader.readexactly(4)
            target_len = int.from_bytes(len_bytes, byteorder="big")
            _ = await reader.readexactly(target_len)

            # Decapsulate mock shared secret
            shared_secret = b"mock-shared-secret-bytes-ml-kem-768-padding".ljust(32, b"\x00")
            
            # Derive gateway key
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            hkdf = HKDF(
                algorithm=HKDF_ALGORITHM,
                length=HKDF_KEY_LENGTH,
                salt=HKDF_SALT,
                info=HKDF_INFO
            )
            self.derived_key = hkdf.derive(shared_secret)

        except Exception as e:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


def test_handshake_integration():
    """
    Integration test: Runs a TCP socket gateway server, initiates client connection,
    mocks the HTTP PQC API call, and verifies both client and gateway converge on
    the exact same derived AES-256 session key.
    """
    async def run():
        gateway = MockGatewayServer(port=9999)
        await gateway.start()

        # Instantiate QVPNClient pointing to our mock gateway
        client = QVPNClient(gateway_ip="127.0.0.1", gateway_port=9999)

        # Mock the PQCClient encapsulate method to return matching values
        mock_ciphertext = b"mock-client-ciphertext-bytes".ljust(1088, b"\x00")
        mock_shared_secret = b"mock-shared-secret-bytes-ml-kem-768-padding".ljust(32, b"\x00")

        # Mock the Gateway REST API calls
        mock_session_id = str(uuid.uuid4())
        mock_pubkey_b64 = base64.b64encode(b"mock-pubkey-bytes").decode("ascii")

        async def mock_post(url, *args, **kwargs):
            m_resp = MagicMock()
            m_resp.status_code = 200
            if "handshake/init" in url:
                m_resp.json.return_value = {
                    "session_id": mock_session_id,
                    "algorithm": "ML-KEM-768",
                    "public_key": mock_pubkey_b64
                }
            elif "handshake/complete" in url:
                m_resp.json.return_value = {
                    "session_id": mock_session_id,
                    "status": "ESTABLISHED"
                }
            return m_resp

        # Mock PQCClient encapsulate, REST HTTP Client post, and EEL UI
        with patch("client.pqc_client.PQCClient.encapsulate", return_value=(mock_ciphertext, mock_shared_secret)), \
             patch("httpx.AsyncClient.post", side_effect=mock_post), \
             patch("client.qvpn_client.DEBUG_MODE_PQC", False), \
             patch("client.qvpn_client.eel") as mock_eel:
            
            mock_eel.trigger_heartbeat.return_value = lambda: None
            
            # Start handshake connection
            await client.connect()

            # Connect to client local proxy server port 8282 to trigger TCP server data plane
            p_reader, p_writer = await asyncio.open_connection("127.0.0.1", 8282)
            p_writer.write(b"localhost:8001\n")
            await p_writer.drain()
            
            # Read confirmation from QVPN client
            ok_line = await p_reader.readline()
            assert ok_line == b"OK\n"
            
            p_writer.close()
            await p_writer.wait_closed()

        # Stop gateway server
        await gateway.stop()

        # Verify handshake success and key convergence
        assert client.state.tunnel_status == "active"
        assert client.session_key is not None
        assert gateway.derived_key is not None
        assert client.session_key == gateway.derived_key

        # Disconnect client
        await client.disconnect()

    asyncio.run(run())


def test_traffic_logging():
    """
    Verifies that all AES encrypted traffic sent to the gateway is logged to input.txt,
    and all decrypted traffic received from the gateway is logged to output.txt.
    """
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    client_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(client_dir, "input.txt")
    output_path = os.path.join(client_dir, "output.txt")

    # Clean up existing test files
    for p in (input_path, output_path):
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    class LogTestingMockGateway:
        def __init__(self, host="127.0.0.1", port=9998):
            self.host = host
            self.port = port
            self.server = None
            self.derived_key = None

        async def handle_connection(self, reader, writer):
            try:
                # 1. Read session_id
                len_bytes = await reader.readexactly(4)
                session_len = int.from_bytes(len_bytes, byteorder="big")
                session_id = (await reader.readexactly(session_len)).decode("utf-8")

                # Echo confirmation
                writer.write(len(session_id).to_bytes(4, byteorder="big"))
                writer.write(session_id.encode("utf-8"))
                await writer.drain()

                # 2. Read target JSON
                len_bytes = await reader.readexactly(4)
                target_len = int.from_bytes(len_bytes, byteorder="big")
                _ = await reader.readexactly(target_len)

                # Derive AES key
                shared_secret = b"mock-shared-secret-bytes-ml-kem-768-padding".ljust(32, b"\x00")
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                hkdf = HKDF(
                    algorithm=HKDF_ALGORITHM,
                    length=HKDF_KEY_LENGTH,
                    salt=HKDF_SALT,
                    info=HKDF_INFO
                )
                self.derived_key = hkdf.derive(shared_secret)

                # 3. Read one data packet from client
                len_bytes = await reader.readexactly(4)
                pkt_len = int.from_bytes(len_bytes, byteorder="big")
                payload = await reader.readexactly(pkt_len)

                # Decrypt data packet
                cipher = AESGCM(self.derived_key)
                nonce = payload[:12]
                ciphertext = payload[12:]
                plaintext = cipher.decrypt(nonce, ciphertext, None)

                # 4. Echo back some response data, encrypted
                resp_plaintext = plaintext + b" echoed-response-data"
                resp_nonce = b"\x00" * 12
                resp_ciphertext = cipher.encrypt(resp_nonce, resp_plaintext, None)
                resp_payload = resp_nonce + resp_ciphertext
                writer.write(len(resp_payload).to_bytes(4, byteorder="big"))
                writer.write(resp_payload)
                await writer.drain()

            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        async def start(self):
            self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)

        async def stop(self):
            if self.server:
                self.server.close()
                await self.server.wait_closed()

    async def run():
        gateway = LogTestingMockGateway(port=9998)
        await gateway.start()

        client = QVPNClient(gateway_ip="127.0.0.1", gateway_port=9998)

        mock_ciphertext = b"mock-client-ciphertext-bytes".ljust(1088, b"\x00")
        mock_shared_secret = b"mock-shared-secret-bytes-ml-kem-768-padding".ljust(32, b"\x00")
        mock_session_id = str(uuid.uuid4())
        mock_pubkey_b64 = base64.b64encode(b"mock-pubkey-bytes").decode("ascii")

        async def mock_post(url, *args, **kwargs):
            m_resp = MagicMock()
            m_resp.status_code = 200
            if "handshake/init" in url:
                m_resp.json.return_value = {
                    "session_id": mock_session_id,
                    "algorithm": "ML-KEM-768",
                    "public_key": mock_pubkey_b64
                }
            elif "handshake/complete" in url:
                m_resp.json.return_value = {
                    "session_id": mock_session_id,
                    "status": "ESTABLISHED"
                }
            return m_resp

        with patch("client.pqc_client.PQCClient.encapsulate", return_value=(mock_ciphertext, mock_shared_secret)), \
             patch("httpx.AsyncClient.post", side_effect=mock_post), \
             patch("client.qvpn_client.DEBUG_MODE_PQC", False), \
             patch("client.qvpn_client.eel") as mock_eel:

            mock_eel.trigger_heartbeat.return_value = lambda: None

            await client.connect()

            # Trigger TCP client data plane
            p_reader, p_writer = await asyncio.open_connection("127.0.0.1", 8282)
            p_writer.write(b"localhost:8001\n")
            await p_writer.drain()

            ok_line = await p_reader.readline()
            assert ok_line == b"OK\n"

            # Send some test payload data through proxy
            p_writer.write(b"hello test log message")
            await p_writer.drain()

            # Read the response echoed back from the gateway (via local proxy server)
            resp = await p_reader.read(1024)
            assert b"hello test log message echoed-response-data" in resp

            p_writer.close()
            await p_writer.wait_closed()

        await gateway.stop()
        await client.disconnect()

        # Assert that input.txt and output.txt exist and contain our data
        assert os.path.exists(input_path), "input.txt was not created"
        assert os.path.exists(output_path), "output.txt was not created"

        with open(input_path, "rb") as f:
            input_content = f.read()
        with open(output_path, "rb") as f:
            output_content = f.read()

        assert b"localhost" in input_content
        assert b"hello test log message" in input_content
        assert b"---SEPARATOR---" in input_content

        assert b"hello test log message echoed-response-data" in output_content
        assert b"---SEPARATOR---" in output_content

    asyncio.run(run())


def test_debug_aes_mode():
    """
    Verifies that when DEBUG_AES is True, traffic is sent completely unencrypted.
    """
    import os
    import json
    import uuid
    import base64
    from unittest.mock import MagicMock, patch

    class PlaintextTestingMockGateway:
        def __init__(self, host="127.0.0.1", port=9997):
            self.host = host
            self.port = port
            self.server = None

        async def handle_connection(self, reader, writer):
            try:
                # 1. Read session_id
                len_bytes = await reader.readexactly(4)
                session_len = int.from_bytes(len_bytes, byteorder="big")
                session_id = (await reader.readexactly(session_len)).decode("utf-8")

                # Echo confirmation
                writer.write(len(session_id).to_bytes(4, byteorder="big"))
                writer.write(session_id.encode("utf-8"))
                await writer.drain()

                # 2. Read target JSON (in plaintext!)
                len_bytes = await reader.readexactly(4)
                target_len = int.from_bytes(len_bytes, byteorder="big")
                target_json = (await reader.readexactly(target_len)).decode("utf-8")
                target_data = json.loads(target_json)
                assert target_data["host"] == "localhost"

                # 3. Read data packet (in plaintext!)
                len_bytes = await reader.readexactly(4)
                pkt_len = int.from_bytes(len_bytes, byteorder="big")
                plaintext = await reader.readexactly(pkt_len)
                assert plaintext == b"hello plaintext debug aes"

                # 4. Echo back plaintext response
                resp = plaintext + b" echoed-plaintext"
                writer.write(len(resp).to_bytes(4, byteorder="big"))
                writer.write(resp)
                await writer.drain()

            except Exception as e:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        async def start(self):
            self.server = await asyncio.start_server(self.handle_connection, self.host, self.port)

        async def stop(self):
            if self.server:
                self.server.close()
                await self.server.wait_closed()

    async def run():
        gateway = PlaintextTestingMockGateway(port=9997)
        await gateway.start()

        client = QVPNClient(gateway_ip="127.0.0.1", gateway_port=9997)

        mock_ciphertext = b"mock-client-ciphertext-bytes".ljust(1088, b"\x00")
        mock_shared_secret = b"mock-shared-secret-bytes-ml-kem-768-padding".ljust(32, b"\x00")
        mock_session_id = str(uuid.uuid4())
        mock_pubkey_b64 = base64.b64encode(b"mock-pubkey-bytes").decode("ascii")

        async def mock_post(url, *args, **kwargs):
            m_resp = MagicMock()
            m_resp.status_code = 200
            if "handshake/init" in url:
                m_resp.json.return_value = {
                    "session_id": mock_session_id,
                    "algorithm": "ML-KEM-768",
                    "public_key": mock_pubkey_b64
                }
            elif "handshake/complete" in url:
                m_resp.json.return_value = {
                    "session_id": mock_session_id,
                    "status": "ESTABLISHED"
                }
            return m_resp

        with patch("client.pqc_client.PQCClient.encapsulate", return_value=(mock_ciphertext, mock_shared_secret)), \
             patch("httpx.AsyncClient.post", side_effect=mock_post), \
             patch("client.qvpn_client.DEBUG_MODE_PQC", False), \
             patch("client.qvpn_client.DEBUG_AES", True), \
             patch("client.qvpn_client.eel") as mock_eel:

            mock_eel.trigger_heartbeat.return_value = lambda: None

            await client.connect()

            p_reader, p_writer = await asyncio.open_connection("127.0.0.1", 8282)
            p_writer.write(b"localhost:8001\n")
            await p_writer.drain()

            ok_line = await p_reader.readline()
            assert ok_line == b"OK\n"

            p_writer.write(b"hello plaintext debug aes")
            await p_writer.drain()

            resp = await p_reader.read(1024)
            assert b"hello plaintext debug aes echoed-plaintext" in resp

            p_writer.close()
            await p_writer.wait_closed()

        await gateway.stop()
        await client.disconnect()

    asyncio.run(run())

