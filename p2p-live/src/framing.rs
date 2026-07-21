//! Length-prefixed message framing, shared by every transport.
//!
//! Both transports carry a byte stream, and both need the same thing from it:
//! discrete, length-bounded messages. This lives in one place so the size cap —
//! the bound on how much memory a peer can make us allocate from one length
//! prefix — cannot drift between them. A second copy of this logic would be a
//! second chance to get that wrong.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

/// Upper bound on a single framed message. Bounds the memory a peer can make the
/// receiver allocate from one length prefix. The bulk transfer streams in chunks
/// well under this; control messages are tiny.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Write one length-prefixed frame, returning the bytes put on the wire.
pub(crate) async fn write_frame<W>(w: &mut W, msg: &[u8]) -> Result<u64, Error>
where
    W: AsyncWrite + Unpin + Send,
{
    if msg.len() > MAX_FRAME_LEN {
        return Err(Error::Session(format!(
            "outbound frame too large: {} > {MAX_FRAME_LEN}",
            msg.len()
        )));
    }
    let len = (msg.len() as u32).to_be_bytes();
    w.write_all(&len)
        .await
        .map_err(|e| Error::Session(format!("write length: {e}")))?;
    w.write_all(msg)
        .await
        .map_err(|e| Error::Session(format!("write payload: {e}")))?;
    Ok((len.len() + msg.len()) as u64)
}

/// Read one frame, distinguishing a clean end-of-stream (`Ok(None)`) from a real
/// error.
///
/// A clean end is the peer closing its side exactly at a frame boundary. Ending
/// *mid*-frame is a truncation and must not be reported as a tidy finish — that
/// distinction is what lets a caller tell "the transfer ended" from "the
/// transfer was cut off".
pub(crate) async fn read_frame_opt<R>(r: &mut R) -> Result<Option<Vec<u8>>, Error>
where
    R: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    let mut got = 0;
    while got < len_buf.len() {
        let n = r
            .read(&mut len_buf[got..])
            .await
            .map_err(|e| Error::Session(format!("read length: {e}")))?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(Error::Session(
                "stream ended part-way through a length prefix".into(),
            ));
        }
        got += n;
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        // Refuse before allocating — this is the whole point of the cap.
        return Err(Error::Session(format!(
            "inbound frame too large: {len} > {MAX_FRAME_LEN}"
        )));
    }

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| Error::Session(format!("read payload: {e}")))?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames round-trip over a plain in-memory pipe, and a clean close at a
    /// frame boundary reads back as end-of-stream rather than an error.
    #[tokio::test]
    async fn frames_round_trip_and_end_cleanly() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);

        let writer = tokio::spawn(async move {
            for msg in [b"one".as_slice(), b"", &[7u8; 5000]] {
                write_frame(&mut a, msg).await.unwrap();
            }
            a.shutdown().await.unwrap();
        });

        assert_eq!(read_frame_opt(&mut b).await.unwrap().unwrap(), b"one");
        assert_eq!(read_frame_opt(&mut b).await.unwrap().unwrap(), b"");
        assert_eq!(
            read_frame_opt(&mut b).await.unwrap().unwrap(),
            vec![7u8; 5000]
        );
        assert_eq!(
            read_frame_opt(&mut b).await.unwrap(),
            None,
            "a clean close at a frame boundary is end-of-stream, not an error"
        );
        writer.await.unwrap();
    }

    /// A stream cut off mid-frame must be an error, never a tidy `None`.
    #[tokio::test]
    async fn a_truncated_frame_is_an_error() {
        // Half a length prefix, then nothing.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0u8, 0]).await.unwrap();
        drop(a);
        assert!(read_frame_opt(&mut b).await.is_err(), "partial prefix");

        // A full prefix promising more payload than ever arrives.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        drop(a);
        assert!(read_frame_opt(&mut b).await.is_err(), "short payload");
    }

    /// The cap is enforced on the way in *before* allocating, and on the way out
    /// before anything reaches the wire.
    #[tokio::test]
    async fn the_size_cap_is_enforced_in_both_directions() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        let err = read_frame_opt(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");

        let (mut a, _b) = tokio::io::duplex(64);
        let err = write_frame(&mut a, &vec![0u8; MAX_FRAME_LEN + 1])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
    }
}
