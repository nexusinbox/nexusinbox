//! Computers connected to the relay, by MCP host. Each one is a yamux
//! session on top of its control connection; the relay opens one stream per
//! incoming connection from a cloud AI.

use futures::future::poll_fn;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

/// Streams a single computer may have open at once.
pub const STREAMS_PER_HOST: usize = 32;

type OpenReply = oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>;

#[derive(Clone)]
struct Handle {
    generation: u64,
    opens: mpsc::Sender<OpenReply>,
    streams: Arc<Semaphore>,
}

#[derive(Default)]
pub struct Registry {
    hosts: Mutex<HashMap<String, Handle>>,
    next: AtomicU64,
}

pub struct Opened {
    pub stream: yamux::Stream,
    pub _permit: OwnedSemaphorePermit,
}

impl Registry {
    pub fn len(&self) -> usize {
        self.hosts.lock().unwrap().len()
    }

    /// Opens a stream to the computer serving `host`, if one is connected
    /// and under its stream limit.
    pub async fn open(&self, host: &str) -> Option<Opened> {
        let handle = self.hosts.lock().unwrap().get(host).cloned()?;
        let permit = handle.streams.try_acquire_owned().ok()?;
        let (tx, rx) = oneshot::channel();
        handle.opens.send(tx).await.ok()?;
        let stream = rx.await.ok()?.ok()?;
        Some(Opened {
            stream,
            _permit: permit,
        })
    }

    /// Serves `host` from this yamux connection until it ends or `ttl`
    /// passes. A newer connection for the same host takes over new streams;
    /// this one keeps running until its own streams are done or it ends.
    pub async fn serve<T>(&self, host: String, conn: yamux::Connection<T>, ttl: std::time::Duration)
    where
        T: futures::AsyncRead + futures::AsyncWrite + Unpin,
    {
        let generation = self.next.fetch_add(1, Ordering::Relaxed);
        let (opens_tx, opens_rx) = mpsc::channel(8);
        self.hosts.lock().unwrap().insert(
            host.clone(),
            Handle {
                generation,
                opens: opens_tx,
                streams: Arc::new(Semaphore::new(STREAMS_PER_HOST)),
            },
        );
        let _ = tokio::time::timeout(ttl, drive(conn, opens_rx)).await;
        let mut hosts = self.hosts.lock().unwrap();
        if hosts.get(&host).is_some_and(|h| h.generation == generation) {
            hosts.remove(&host);
        }
    }
}

/// Runs the yamux connection: opens outbound streams on request and drops
/// any stream the computer tries to open (it never should).
async fn drive<T>(mut conn: yamux::Connection<T>, mut opens: mpsc::Receiver<OpenReply>)
where
    T: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut pending: Option<OpenReply> = None;
    // Once a newer connection takes over, no new streams arrive here; keep
    // carrying the open ones until the computer closes this connection.
    let mut replaced = false;
    poll_fn(|cx| loop {
        match conn.poll_next_inbound(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                drop(stream);
                continue;
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
            Poll::Pending => {}
        }
        if pending.is_none() && !replaced {
            match opens.poll_recv(cx) {
                Poll::Ready(Some(reply)) => pending = Some(reply),
                Poll::Ready(None) => replaced = true,
                Poll::Pending => {}
            }
        }
        if let Some(reply) = pending.take() {
            match conn.poll_new_outbound(cx) {
                Poll::Ready(result) => {
                    let failed = result.is_err();
                    let _ = reply.send(result);
                    if failed {
                        return Poll::Ready(());
                    }
                    continue;
                }
                Poll::Pending => pending = Some(reply),
            }
        }
        return Poll::Pending;
    })
    .await;
}
