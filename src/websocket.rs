use futures_util::{SinkExt, StreamExt};
use thiserror::Error;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

use crate::{
    client::{BoxedIo, Client, ClientError},
    request::Request,
};

pub struct WebSocketBuilder {
    pub(crate) client: Client,
    pub(crate) request: Request,
    pub(crate) read_buffer_size: Option<usize>,
    pub(crate) write_buffer_size: Option<usize>,
}

impl WebSocketBuilder {
    pub fn new(client: Client, url: impl Into<String>) -> Self {
        Self {
            client,
            request: Request::get(url),
            read_buffer_size: None,
            write_buffer_size: None,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.header(name, value);
        self
    }

    pub fn read_buffer_size(mut self, size: usize) -> Self {
        self.read_buffer_size = Some(size);
        self
    }

    pub fn write_buffer_size(mut self, size: usize) -> Self {
        self.write_buffer_size = Some(size);
        self
    }

    pub async fn connect(self) -> Result<WebSocket, WebSocketError> {
        self.client.clone().connect_websocket(self).await
    }

    pub(crate) fn websocket_config(&self) -> Option<WebSocketConfig> {
        let mut config = WebSocketConfig::default();
        let mut customized = false;
        if let Some(size) = self.read_buffer_size {
            config.read_buffer_size = size;
            customized = true;
        }
        if let Some(size) = self.write_buffer_size {
            config.write_buffer_size = size;
            customized = true;
        }
        customized.then_some(config)
    }
}

pub struct WebSocket {
    inner: WebSocketStream<BoxedIo>,
}

impl WebSocket {
    pub(crate) fn new(inner: WebSocketStream<BoxedIo>) -> Self {
        Self { inner }
    }

    pub async fn send_text(&mut self, value: impl Into<String>) -> Result<(), WebSocketError> {
        self.inner
            .send(Message::Text(value.into().into()))
            .await
            .map_err(WebSocketError::Http)
    }

    pub async fn recv_text(&mut self) -> Result<Option<String>, WebSocketError> {
        while let Some(message) = self.inner.next().await {
            let message = message.map_err(WebSocketError::Http)?;
            if let Message::Text(text) = message {
                return Ok(Some(text.to_string()));
            }
        }

        Ok(None)
    }

    pub async fn close(mut self) -> Result<(), WebSocketError> {
        self.inner.close(None).await.map_err(WebSocketError::Http)
    }
}

#[derive(Debug, Error)]
pub enum WebSocketError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Http(#[from] tokio_tungstenite::tungstenite::Error),
}

impl From<WebSocketBuilder> for Request {
    fn from(value: WebSocketBuilder) -> Self {
        value.request
    }
}
