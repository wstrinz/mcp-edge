//! Length-prefixed framing (PHASE4.md §2.3), generic over tokio I/O so it works
//! on iroh streams and in-memory pipes alike.
//!
//! ```text
//! field      = u32 big-endian length || bytes      (length checked before allocation)
//! request    = field(meta) field(body) FIN          (no trailing byte allowed)
//! response   = field(meta) field(chunk)* 0x00000000 FIN
//! ```

use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A length prefix exceeds the field's cap (nothing was allocated).
    TooLarge,
    /// The stream ended inside a field (or before a required field).
    Truncated,
    /// Bytes followed the end of a request (or the response terminator).
    TrailingBytes,
    /// Stream/connection error (reset, connection lost, ...).
    Io,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FrameError::TooLarge => "frame exceeds its size limit",
            FrameError::Truncated => "frame truncated",
            FrameError::TrailingBytes => "trailing bytes after the last frame",
            FrameError::Io => "stream error",
        })
    }
}
impl std::error::Error for FrameError {}

fn map_read(e: std::io::Error) -> FrameError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        FrameError::Truncated
    } else {
        FrameError::Io
    }
}

/// Write one field. Refuses (without writing) if `bytes` exceeds `cap`.
pub async fn write_field<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
    cap: usize,
) -> Result<(), FrameError> {
    if bytes.len() > cap || bytes.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut header = [0u8; 4];
    header.copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    w.write_all(&header).await.map_err(|_| FrameError::Io)?;
    if !bytes.is_empty() {
        w.write_all(bytes).await.map_err(|_| FrameError::Io)?;
    }
    Ok(())
}

/// Write the zero-length response terminator.
pub async fn write_terminator<W: AsyncWrite + Unpin>(w: &mut W) -> Result<(), FrameError> {
    write_field(w, &[], 0).await
}

/// Read one field. The length prefix is compared with `cap` before the buffer
/// is allocated.
pub async fn read_field<R: AsyncRead + Unpin>(
    r: &mut R,
    cap: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await.map_err(map_read)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > cap {
        return Err(FrameError::TooLarge);
    }
    let mut data = vec![0u8; length];
    r.read_exact(&mut data).await.map_err(map_read)?;
    Ok(data)
}

/// Require end of stream (FIN) now: any further byte is `TrailingBytes`.
pub async fn expect_end<R: AsyncRead + Unpin>(r: &mut R) -> Result<(), FrameError> {
    let mut tail = [0u8; 1];
    match r.read(&mut tail).await {
        Ok(0) => Ok(()),
        Ok(_) => Err(FrameError::TrailingBytes),
        Err(_) => Err(FrameError::Io),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_and_terminator() {
        let mut buf = Vec::new();
        write_field(&mut buf, b"hello", 5).await.unwrap();
        write_terminator(&mut buf).await.unwrap();
        assert_eq!(buf, b"\0\0\0\x05hello\0\0\0\0");
        let mut r = buf.as_slice();
        assert_eq!(read_field(&mut r, 5).await.unwrap(), b"hello");
        assert_eq!(read_field(&mut r, 16).await.unwrap(), b"");
        expect_end(&mut r).await.unwrap();
    }

    #[tokio::test]
    async fn cap_at_limit_and_plus_one() {
        let mut buf = Vec::new();
        write_field(&mut buf, &[7u8; 10], 10).await.unwrap();
        assert_eq!(read_field(&mut buf.as_slice(), 10).await.unwrap().len(), 10);
        assert_eq!(
            read_field(&mut buf.as_slice(), 9).await,
            Err(FrameError::TooLarge)
        );
        let mut out = Vec::new();
        assert_eq!(
            write_field(&mut out, &[0u8; 11], 10).await,
            Err(FrameError::TooLarge)
        );
        assert!(out.is_empty(), "nothing written for an oversized field");
    }

    #[tokio::test]
    async fn huge_length_is_rejected_before_allocation() {
        // A 4 GiB claim with no data behind it: must fail on the cap, not try
        // to allocate or wait for data.
        let bytes = [0xffu8, 0xff, 0xff, 0xff];
        assert_eq!(
            read_field(&mut bytes.as_slice(), 64 * 1024).await,
            Err(FrameError::TooLarge)
        );
    }

    #[tokio::test]
    async fn truncation_and_trailing_bytes() {
        let bytes = [0u8, 0, 0, 5, b'a', b'b'];
        assert_eq!(
            read_field(&mut bytes.as_slice(), 16).await,
            Err(FrameError::Truncated)
        );
        let bytes = [0u8, 0];
        assert_eq!(
            read_field(&mut bytes.as_slice(), 16).await,
            Err(FrameError::Truncated)
        );
        assert_eq!(
            read_field(&mut [].as_slice(), 16).await,
            Err(FrameError::Truncated)
        );
        assert_eq!(
            expect_end(&mut [1u8].as_slice()).await,
            Err(FrameError::TrailingBytes)
        );
    }
}
