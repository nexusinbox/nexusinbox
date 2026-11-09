//! Small I/O helpers: replaying bytes already read, copying with an idle
//! limit, and reading one bounded line.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

/// A stream that first yields `prefix`, then reads from `inner`.
pub struct Prefixed<T> {
    prefix: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> Prefixed<T> {
    pub fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Copies both ways until either side closes or nothing has moved in
/// either direction for `idle`. Returns the bytes moved.
pub async fn pipe<A, B>(a: A, b: B, idle: Duration) -> u64
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let moved = Arc::new(AtomicU64::new(0));
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let one = copy_half(ar, bw, start, last.clone(), moved.clone(), idle);
    let two = copy_half(br, aw, start, last.clone(), moved.clone(), idle);
    tokio::select! {
        _ = one => {}
        _ = two => {}
    }
    moved.load(Ordering::Relaxed)
}

async fn copy_half<R, W>(
    mut from: R,
    mut to: W,
    start: Instant,
    last: Arc<AtomicU64>,
    moved: Arc<AtomicU64>,
    idle: Duration,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(idle, from.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                if to.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                moved.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => {
                // Quiet on this side; stop only if the other side is too.
                let since = start.elapsed().as_millis() as u64 - last.load(Ordering::Relaxed);
                if since >= idle.as_millis() as u64 {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown().await;
}

/// Reads one `\n`-terminated line of at most `max` bytes, byte by byte so
/// nothing after the line is consumed.
pub async fn read_line<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let b = r.read_u8().await?;
        if b == b'\n' {
            return Ok(line);
        }
        if line.len() >= max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        line.push(b);
    }
}

/// Reads a PROXY protocol v1 header and returns the client address.
pub async fn read_proxy_v1<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<std::net::IpAddr> {
    let line = read_line(r, 107).await?;
    let line = std::str::from_utf8(&line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad PROXY header"))?;
    let mut parts = line.trim_end_matches('\r').split(' ');
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "bad PROXY header");
    if parts.next() != Some("PROXY") {
        return Err(bad());
    }
    match parts.next() {
        Some("TCP4") | Some("TCP6") => {}
        _ => return Err(bad()),
    }
    parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prefixed_replays_then_reads() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b" world").await.unwrap();
        drop(client);
        let mut s = Prefixed::new(b"hello".to_vec(), server);
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }

    #[tokio::test]
    async fn proxy_header() {
        let mut r: &[u8] = b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 8443\r\nrest";
        let ip = read_proxy_v1(&mut r).await.unwrap();
        assert_eq!(ip.to_string(), "203.0.113.7");
        assert_eq!(r, b"rest");
        let mut r: &[u8] = b"GET / HTTP/1.1\r\n";
        assert!(read_proxy_v1(&mut r).await.is_err());
    }

    #[tokio::test]
    async fn read_line_is_bounded() {
        let mut r: &[u8] = b"abc\nnext";
        assert_eq!(read_line(&mut r, 8).await.unwrap(), b"abc");
        assert_eq!(r, b"next");
        let mut r: &[u8] = b"0123456789\n";
        assert!(read_line(&mut r, 4).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn pipe_stops_when_idle() {
        let (a, _a_peer) = tokio::io::duplex(64);
        let (b, _b_peer) = tokio::io::duplex(64);
        let moved = pipe(a, b, Duration::from_secs(5)).await;
        assert_eq!(moved, 0);
    }
}
