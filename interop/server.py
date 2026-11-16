"""HTTP/3 server for interoperability checks against an independent implementation."""

import argparse
import asyncio
import logging

import pylsqpack

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import encode_uint_var
from aioquic.h3.connection import FrameType, H3Connection, encode_frame
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.quic.events import HandshakeCompleted
from aioquic.tls import CipherSuite


class InteropH3(H3Connection):
    def _init_connection(self):
        # aioquic 1.8 defaults to a zero-capacity table. Enable the independent
        # decoder in this test fixture so the client can exercise QPACK inserts.
        self._max_table_capacity = 4096
        self._blocked_streams = 8
        self._decoder = pylsqpack.Decoder(self._max_table_capacity, self._blocked_streams)
        super()._init_connection()


class InteropProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = InteropH3(self._quic)
        self.key_update = False

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.key_update = config.key_update
        for request in self.h3.handle_event(event):
            if isinstance(request, HeadersReceived):
                self.respond(request)

    def respond(self, request):
        headers = dict(request.headers)
        path = headers.get(b":path")
        if self.key_update:
            self._quic.request_key_update()
            self.key_update = False
        if path == b"/push":
            promised = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", headers[b":authority"]),
                (b":path", b"/promised"),
            ]
            # aioquic 1.8 removed its server push helper. Construct the RFC 9114
            # frames while still using aioquic for QUIC and its QPACK encoder.
            push_id = encode_uint_var(0)
            promise = self.h3._encode_headers(request.stream_id, promised)
            self._quic.send_stream_data(
                request.stream_id, encode_frame(FrameType.PUSH_PROMISE, push_id + promise)
            )
            pushed = self._quic.get_next_available_stream_id(is_unidirectional=True)
            fields = self.h3._encode_headers(pushed, [(b":status", b"200")])
            self._quic.send_stream_data(
                pushed,
                encode_uint_var(1) + push_id + encode_frame(FrameType.HEADERS, fields)
                + encode_frame(FrameType.DATA, b"hello from push\n"),
                end_stream=True,
            )
        if path == b"/goaway":
            self._quic.send_stream_data(
                self.h3._local_control_stream_id,
                encode_frame(FrameType.GOAWAY, encode_uint_var(request.stream_id + 4)),
            )
        body = b"hello from aioquic h3\n"
        if path == b"/large":
            body = b"0123456789abcdef" * 65536
        self.h3.send_headers(
            request.stream_id,
            [(b":status", b"200"), (b"content-type", b"text/plain")],
        )
        self.h3.send_data(request.stream_id, body, end_stream=True)


async def main():
    cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    cfg.load_cert_chain(config.cert, config.key)
    if config.chacha:
        cfg.cipher_suites = [CipherSuite.CHACHA20_POLY1305_SHA256]
    if config.v2:
        cfg.supported_versions = [QuicProtocolVersion.VERSION_2]
    tickets = {}

    def save_ticket(ticket):
        tickets[ticket.ticket] = ticket

    def load_ticket(identity):
        return None if config.reject_resumption else tickets.pop(identity, None)

    await serve(
        "127.0.0.1",
        config.port,
        configuration=cfg,
        create_protocol=InteropProtocol,
        retry=config.retry,
        session_ticket_handler=save_ticket,
        session_ticket_fetcher=load_ticket,
    )
    print(f"HTTP/3 server listening on 127.0.0.1:{config.port}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--cert", default="cert.pem")
    parser.add_argument("--key", default="key.pem")
    parser.add_argument("--retry", action="store_true")
    parser.add_argument("--v2", action="store_true")
    parser.add_argument("--reject-resumption", action="store_true")
    parser.add_argument("--chacha", action="store_true")
    parser.add_argument("--key-update", action="store_true")
    config = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
