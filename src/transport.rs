use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Generic transport trait that is used in [`crate::protocol::peer_wire::PeerConnection`] as a transport layer.
/// Implementing this makes it easy to use Peer Wire protocol on any transportation layer.
#[async_trait]
pub trait Transport: AsyncWriteExt + AsyncReadExt + Send + Sync + Unpin {
    /// Waits for the socket to become writable.
    async fn writable(&self) -> io::Result<()>;
    async fn readable(&self) -> io::Result<()>;
    fn try_write(&self, buf: &[u8]) -> io::Result<usize>;
    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

/// [`TcpStream`] implementation of [`Transport`].
#[async_trait]
impl Transport for TcpStream {
    async fn writable(&self) -> io::Result<()> {
        self.writable().await
    }

    async fn readable(&self) -> io::Result<()> {
        self.readable().await
    }

    fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        self.try_write(buf)
    }

    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.try_read(buf)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr()
    }
}