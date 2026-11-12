use dybw_core::ports::{EventSocket, Events, Frame, PortError};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

/// The hub sends small notifications; the core refuses anything over 1 MiB too.
const MAX_MESSAGE: usize = 1 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The notifications hub over a WebSocket (rustls, the system's roots). The
/// client never follows a redirect: any answer but `101` fails the connect.
/// The URL carries the access token, so no error here ever includes it.
pub struct WsEvents;

pub struct WsSocket(WebSocketStream<MaybeTlsStream<TcpStream>>);

fn failed(e: impl std::fmt::Display) -> PortError {
    PortError(format!("notifications: {e}"))
}

/// rustls with aws-lc-rs, named here rather than taken from whichever
/// provider the build happens to enable, and the system's roots (as reqwest).
fn tls() -> Result<Arc<rustls::ClientConfig>, PortError> {
    let mut roots = rustls::RootCertStore::empty();
    // An empty store fails every handshake with an unknown issuer.
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(failed)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

impl Events for WsEvents {
    type Socket = WsSocket;

    async fn connect(&self, url: &str) -> Result<WsSocket, PortError> {
        let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        // A `ws:` URL (loopback only) stays plain whatever the connector.
        let connector = Connector::Rustls(tls()?);
        let connecting = tokio_tungstenite::connect_async_tls_with_config(url, Some(config), true, Some(connector));
        match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok((socket, _))) => Ok(WsSocket(socket)),
            Ok(Err(e)) => Err(failed(e)),
            Err(_) => Err(failed("the connection timed out")),
        }
    }
}

impl EventSocket for WsSocket {
    async fn send(&mut self, frame: Frame) -> Result<(), PortError> {
        let message = match frame {
            Frame::Text(t) => Message::text(t),
            Frame::Binary(b) => Message::binary(b),
        };
        self.0.send(message).await.map_err(failed)
    }

    /// Cancel-safe: `next` keeps a partly read frame in the stream.
    async fn recv(&mut self) -> Option<Result<Frame, PortError>> {
        loop {
            return match self.0.next().await? {
                Ok(Message::Text(t)) => Some(Ok(Frame::Text(t.as_str().to_owned()))),
                Ok(Message::Binary(b)) => Some(Ok(Frame::Binary(b.to_vec()))),
                Ok(Message::Close(_)) => None,
                // Pings are answered by tungstenite itself.
                Ok(_) => continue,
                Err(e) => Some(Err(failed(e))),
            };
        }
    }

    async fn close(&mut self) {
        let _ = self.0.close(None).await;
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_socket_passes_frames_skips_pings_and_ends_on_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(listener.accept().await.unwrap().0).await.unwrap();
            let got = ws.next().await.unwrap().unwrap();
            ws.send(Message::Ping(vec![1].into())).await.unwrap();
            ws.send(Message::text("t")).await.unwrap();
            ws.send(Message::binary(vec![2, 3])).await.unwrap();
            ws.close(None).await.unwrap();
            got
        });
        let mut socket = WsEvents.connect(&url).await.unwrap();
        socket.send(Frame::Text("hello".into())).await.unwrap();
        assert_eq!(socket.recv().await.unwrap().unwrap(), Frame::Text("t".into()));
        assert_eq!(socket.recv().await.unwrap().unwrap(), Frame::Binary(vec![2, 3]));
        assert!(socket.recv().await.is_none(), "a close frame ends the socket");
        assert_eq!(server.await.unwrap(), Message::text("hello"));
        socket.close().await;
        assert!(socket.send(Frame::Binary(vec![1])).await.is_err(), "closed");
    }

    #[tokio::test]
    async fn a_dropped_connection_is_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let ws = tokio_tungstenite::accept_async(listener.accept().await.unwrap().0).await.unwrap();
            drop(ws); // no closing handshake
        });
        let mut socket = WsEvents.connect(&url).await.unwrap();
        assert!(socket.recv().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_redirect_is_refused_and_the_error_holds_no_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub?access_token=SECRET-TOKEN", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ =
                s.write_all(b"HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n").await;
        });
        let err = WsEvents.connect(&url).await.err().unwrap();
        assert!(err.0.contains("302"), "{err}");
        assert!(!err.0.contains("SECRET-TOKEN"), "{err}");
    }

    #[tokio::test]
    async fn a_wss_url_goes_through_rustls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("wss://{}/hub", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s.write_all(b"not tls\r\n\r\n").await;
        });
        let err = WsEvents.connect(&url).await.err().unwrap();
        assert!(err.0.starts_with("notifications: "), "{err}");
        let tls = tls().unwrap();
        let ours = rustls::crypto::aws_lc_rs::default_provider();
        assert_eq!(tls.crypto_provider().cipher_suites, ours.cipher_suites, "aws-lc-rs, pinned");
        assert_eq!(failed(rustls::Error::HandshakeNotComplete).0, "notifications: handshake not complete");
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_never_answers_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/hub", listener.local_addr().unwrap());
        let err = WsEvents.connect(&url).await.err().unwrap();
        assert!(err.0.contains("timed out"), "{err}");
        drop(listener);
    }
}
