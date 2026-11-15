import asyncio, logging
from cryptography.hazmat.primitives import serialization
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

class P(QuicConnectionProtocol):
    def __init__(self,*a,**k):
        super().__init__(*a,**k)
        self.h3=H3Connection(self._quic)
    def quic_event_received(self, event):
        try:
            priv = getattr(self._quic.tls, '_x25519_private_key', None)
            if priv is not None and not getattr(self, '_logged', False):
                self._logged = True
                logging.info('SRVPRIV %s' % priv.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                    serialization.NoEncryption()).hex())
        except Exception:
            pass
        logging.info('EVT %s sd=%s sid=%s data=%s fin=%s' % (type(event).__name__, getattr(event,'stream_id',-1), getattr(event,'stream_id',-1), getattr(event,'data',b'').hex() + ' LEN=' + str(len(getattr(event,'data',b''))), getattr(event,'end_stream','')))
        try:
            evs = self.h3.handle_event(event)
            logging.info('H3EV %d' % len(evs))
        except Exception as exc:
            logging.info('H3ERR %r' % exc)
            evs = []
        for e in evs:
            if isinstance(e, HeadersReceived):
                self.h3.send_headers(stream_id=e.stream_id, headers=[(b':status',b'200'),(b'content-type',b'text/plain')])
                self.h3.send_data(stream_id=e.stream_id, data=b'hello from aioquic h3\n', end_stream=True)

async def main():
    cfg=QuicConfiguration(is_client=False, alpn_protocols=['h3'])
    cfg.load_cert_chain('cert.pem','key.pem')
    cfg.secrets_log_file = open('keys.log','w',buffering=1)
    await serve('127.0.0.1', 4433, configuration=cfg, create_protocol=P)
    await asyncio.Future()
asyncio.run(main())
