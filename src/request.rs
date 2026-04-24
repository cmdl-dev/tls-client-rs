use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};

use crate::client::ClientError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

impl HeaderEntry {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<HeaderEntry>,
    pub body: Option<Vec<u8>>,
}

impl Request {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::GET, url)
    }

    pub fn head(url: impl Into<String>) -> Self {
        Self::new(Method::HEAD, url)
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self::new(Method::POST, url)
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HeaderEntry::new(name, value));
        self
    }

    pub fn with_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push(HeaderEntry::new(name, value));
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub(crate) fn has_header(&self, needle: &str) -> bool {
        self.headers
            .iter()
            .any(|entry| entry.name.eq_ignore_ascii_case(needle))
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Response {
    pub(crate) fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            version,
            headers,
            body,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub async fn text(self) -> Result<String, ClientError> {
        String::from_utf8(self.body)
            .map_err(|err| ClientError::Http(format!("response body was not valid utf-8: {err}")))
    }

    pub async fn bytes(self) -> Result<Vec<u8>, ClientError> {
        Ok(self.body)
    }
}

pub(crate) fn headers_to_map(headers: &[HeaderEntry]) -> Result<HeaderMap, ClientError> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for entry in headers {
        let name = HeaderName::from_bytes(entry.name.as_bytes())
            .map_err(|err| ClientError::InvalidHeaderName(entry.name.clone(), err.to_string()))?;
        let value = HeaderValue::from_str(&entry.value)
            .map_err(|err| ClientError::InvalidHeaderValue(entry.name.clone(), err.to_string()))?;
        map.append(name, value);
    }
    Ok(map)
}
