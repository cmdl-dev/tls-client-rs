use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct BandwidthTracker {
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&self) {
        self.read_bytes.store(0, Ordering::Relaxed);
        self.write_bytes.store(0, Ordering::Relaxed);
    }

    pub fn read_bytes(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed)
    }

    pub fn write_bytes(&self) -> u64 {
        self.write_bytes.load(Ordering::Relaxed)
    }

    pub fn total_bandwidth(&self) -> u64 {
        self.read_bytes() + self.write_bytes()
    }

    pub fn track_stream<T>(self: &std::sync::Arc<Self>, inner: T) -> TrackedStream<T> {
        TrackedStream {
            inner,
            tracker: self.clone(),
        }
    }

    pub(crate) fn add_read(&self, count: usize) {
        self.read_bytes.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(crate) fn add_write(&self, count: usize) {
        self.write_bytes.fetch_add(count as u64, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub struct NoopBandwidthTracker;

impl NoopBandwidthTracker {
    pub fn new() -> Self {
        Self
    }

    pub fn reset(&self) {}

    pub fn read_bytes(&self) -> u64 {
        0
    }

    pub fn write_bytes(&self) -> u64 {
        0
    }

    pub fn total_bandwidth(&self) -> u64 {
        0
    }

    pub fn track_stream<T>(&self, inner: T) -> T {
        inner
    }
}

#[derive(Debug)]
pub struct TrackedStream<T> {
    inner: T,
    tracker: std::sync::Arc<BandwidthTracker>,
}

impl<T> TrackedStream<T> {
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> tokio::io::AsyncRead for TrackedStream<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let read = buf.filled().len().saturating_sub(before);
                self.tracker.add_read(read);
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> tokio::io::AsyncWrite for TrackedStream<T>
where
    T: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(written)) => {
                self.tracker.add_write(written);
                std::task::Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
