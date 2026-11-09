//! Reads the server name from a TLS ClientHello without terminating TLS.
//! Only the SNI is looked at; everything is forwarded byte for byte.

/// Outcome of looking at the bytes received so far.
#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
    /// More bytes are needed.
    NeedMore,
    /// A complete ClientHello; the server name, if it sent one.
    Done(Option<String>),
    /// Not a TLS ClientHello.
    Invalid,
}

/// Largest ClientHello we wait for (it may span several records).
pub const MAX_HELLO: usize = 16 * 1024;

pub fn parse(buf: &[u8]) -> Hello {
    // Gather the handshake bytes from consecutive handshake records.
    let mut handshake = Vec::new();
    let mut pos = 0;
    loop {
        if buf.len() < pos + 5 {
            return Hello::NeedMore;
        }
        if buf[pos] != 0x16 || buf[pos + 1] != 0x03 {
            return Hello::Invalid;
        }
        let len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if len == 0 || len > 16 * 1024 + 256 {
            return Hello::Invalid;
        }
        if buf.len() < pos + 5 + len {
            return Hello::NeedMore;
        }
        handshake.extend_from_slice(&buf[pos + 5..pos + 5 + len]);
        pos += 5 + len;
        if handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Hello::Invalid;
            }
            let body = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
            if body + 4 > MAX_HELLO {
                return Hello::Invalid;
            }
            if handshake.len() >= body + 4 {
                return match server_name(&handshake[4..body + 4]) {
                    Some(name) => Hello::Done(name),
                    None => Hello::Invalid,
                };
            }
        }
        if pos >= MAX_HELLO {
            return Hello::Invalid;
        }
    }
}

/// `None` when the body is malformed; `Some(None)` when it has no SNI.
fn server_name(body: &[u8]) -> Option<Option<String>> {
    let mut r = Reader(body);
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    let n = r.u8()? as usize;
    r.take(n)?; // session id
    let n = r.u16()? as usize;
    r.take(n)?; // cipher suites
    let n = r.u8()? as usize;
    r.take(n)?; // compression methods
    if r.0.is_empty() {
        return Some(None);
    }
    let n = r.u16()? as usize;
    let mut ext = Reader(r.take(n)?);
    while !ext.0.is_empty() {
        let kind = ext.u16()?;
        let n = ext.u16()? as usize;
        let data = ext.take(n)?;
        if kind != 0 {
            continue;
        }
        let mut list = Reader(data);
        let n = list.u16()? as usize;
        let mut names = Reader(list.take(n)?);
        while !names.0.is_empty() {
            let name_type = names.u8()?;
            let n = names.u16()? as usize;
            let name = names.take(n)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name).ok()?;
                if name.is_empty() || !name.is_ascii() {
                    return None;
                }
                return Some(Some(name.to_ascii_lowercase()));
            }
        }
        return Some(None);
    }
    Some(None)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A real ClientHello from rustls for `name`.
    fn client_hello(name: &str) -> Vec<u8> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots = rustls::RootCertStore::empty();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from(name.to_string()).unwrap(),
        )
        .unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn reads_the_server_name() {
        let hello = client_hello("k3x9q7abcd.mcp.agent-inbox.ai");
        assert_eq!(
            parse(&hello),
            Hello::Done(Some("k3x9q7abcd.mcp.agent-inbox.ai".into()))
        );
    }

    #[test]
    fn waits_for_the_whole_hello() {
        let hello = client_hello("relay.agent-inbox.ai");
        for cut in [0, 3, 5, 40, hello.len() - 1] {
            assert_eq!(parse(&hello[..cut]), Hello::NeedMore, "cut at {cut}");
        }
    }

    #[test]
    fn a_hello_split_over_two_records() {
        let hello = client_hello("relay.agent-inbox.ai");
        let body = &hello[5..];
        let (a, b) = body.split_at(50);
        let mut split = Vec::new();
        for part in [a, b] {
            split.extend_from_slice(&[0x16, 0x03, 0x01]);
            split.extend_from_slice(&(part.len() as u16).to_be_bytes());
            split.extend_from_slice(part);
        }
        assert_eq!(
            parse(&split),
            Hello::Done(Some("relay.agent-inbox.ai".into()))
        );
    }

    #[test]
    fn rejects_what_is_not_tls() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Hello::Invalid);
        assert_eq!(parse(&[0x16, 0x03, 0x01, 0x00, 0x00]), Hello::Invalid);
        let mut hello = client_hello("relay.agent-inbox.ai");
        hello[5] = 0x02; // not a ClientHello
        assert_eq!(parse(&hello), Hello::Invalid);
    }
}
