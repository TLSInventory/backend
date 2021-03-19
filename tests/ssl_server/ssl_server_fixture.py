import pytest
import ssl
import os
from os.path import join as pjoin
cur_dir = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture(scope="session")
def httpserver_ssl_context():
    protocol = None
    for name in ("PROTOCOL_TLS_SERVER", "PROTOCOL_TLS", "PROTOCOL_TLSv1_2"):
        if hasattr(ssl, name):
            protocol = getattr(ssl, name)
            break

    assert protocol is not None, "Unable to obtain TLS protocol"

    return ssl.SSLContext(protocol)


@pytest.fixture
def httpserver_ssl_add_cert(httpserver):
    server_crt = pjoin(cur_dir, "localhost.cert")
    server_key = pjoin(cur_dir, "localhost.key")
    context = httpserver.ssl_context

    assert context is not None, \
        "SSLContext not set. The session was probably started with a test that did not define an SSLContext."

    httpserver.ssl_context.load_cert_chain(server_crt, server_key)



