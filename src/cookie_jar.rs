use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, SystemTime},
};

use cookie::{Cookie, Expiration, SameSite};
use http::HeaderMap;
use url::Url;

#[derive(Clone, Copy, Debug, Default)]
pub struct CookieJarOptions {
    pub skip_existing: bool,
}

#[derive(Clone, Debug)]
struct StoredCookie {
    cookie: Cookie<'static>,
    host_only: bool,
    expires_at: Option<SystemTime>,
}

impl StoredCookie {
    fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
}

#[derive(Default, Debug)]
pub struct CookieJar {
    options: CookieJarOptions,
    cookies: RwLock<HashMap<(String, String, String), StoredCookie>>,
}

impl CookieJar {
    pub fn new(options: CookieJarOptions) -> Self {
        Self {
            options,
            cookies: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_cookies(&self, url: &Url, cookies: &[Cookie<'static>]) {
        let now = SystemTime::now();
        let mut jar = self.cookies.write().expect("cookie jar poisoned");

        for cookie in cookies {
            let mut cookie = cookie.clone();
            let domain = cookie
                .domain()
                .map(|value| value.trim_start_matches('.').to_ascii_lowercase())
                .unwrap_or_else(|| url.host_str().unwrap_or_default().to_ascii_lowercase());
            let path = normalize_path(cookie.path().unwrap_or_else(|| default_path(url)));
            let key = (domain.clone(), path.clone(), cookie.name().to_string());
            let expires_at = compute_expiration(&cookie, now);
            let host_only = cookie.domain().is_none();

            if is_delete_cookie(&cookie, expires_at, now) {
                jar.remove(&key);
                continue;
            }

            if self.options.skip_existing && jar.contains_key(&key) {
                continue;
            }

            cookie.set_domain(domain.clone());
            cookie.set_path(path.clone());

            jar.insert(
                key,
                StoredCookie {
                    cookie,
                    host_only,
                    expires_at,
                },
            );
        }
    }

    pub fn set_from_response_headers(&self, url: &Url, headers: &HeaderMap) {
        let parsed: Vec<Cookie<'static>> = headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| Cookie::parse(value.to_owned()).ok())
            .map(Cookie::into_owned)
            .collect();

        self.set_cookies(url, &parsed);
    }

    pub fn get_cookies(&self, url: &Url) -> Vec<Cookie<'static>> {
        let now = SystemTime::now();
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let path = normalize_path(url.path());
        let mut expired_keys = Vec::new();
        let mut values = Vec::new();

        let jar = self.cookies.read().expect("cookie jar poisoned");
        for (key, stored) in jar.iter() {
            if stored.is_expired(now) {
                expired_keys.push(key.clone());
                continue;
            }

            if !domain_matches(&host, &key.0, stored.host_only) {
                continue;
            }

            if !path_matches(&path, &key.1) {
                continue;
            }

            values.push(stored.cookie.clone());
        }
        drop(jar);

        if !expired_keys.is_empty() {
            let mut jar = self.cookies.write().expect("cookie jar poisoned");
            for key in expired_keys {
                jar.remove(&key);
            }
        }

        values.sort_by(|left, right| {
            right
                .path()
                .unwrap_or("")
                .len()
                .cmp(&left.path().unwrap_or("").len())
        });
        values
    }

    pub fn cookie_header_value(&self, url: &Url) -> Option<String> {
        let cookies = self.get_cookies(url);
        if cookies.is_empty() {
            return None;
        }

        Some(
            cookies
                .into_iter()
                .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

impl Clone for CookieJar {
    fn clone(&self) -> Self {
        let values = self.cookies.read().expect("cookie jar poisoned").clone();
        Self {
            options: self.options,
            cookies: RwLock::new(values),
        }
    }
}

fn compute_expiration(cookie: &Cookie<'_>, now: SystemTime) -> Option<SystemTime> {
    if let Some(max_age) = cookie.max_age() {
        if max_age.whole_seconds() <= 0 {
            return Some(now);
        }
        return Some(now + Duration::from_secs(max_age.whole_seconds() as u64));
    }

    match cookie.expires() {
        Some(Expiration::DateTime(date_time)) => {
            let unix = date_time.unix_timestamp();
            if unix < 0 {
                Some(now)
            } else {
                Some(SystemTime::UNIX_EPOCH + Duration::from_secs(unix as u64))
            }
        }
        _ => None,
    }
}

fn is_delete_cookie(cookie: &Cookie<'_>, expires_at: Option<SystemTime>, now: SystemTime) -> bool {
    cookie
        .max_age()
        .is_some_and(|value| value.whole_seconds() <= 0)
        || expires_at.is_some_and(|expires_at| expires_at <= now)
}

fn domain_matches(host: &str, domain: &str, host_only: bool) -> bool {
    if host_only {
        host == domain
    } else {
        host == domain || host.ends_with(&format!(".{domain}"))
    }
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    request_path == cookie_path
        || request_path.starts_with(cookie_path)
        || (cookie_path == "/" && request_path.starts_with('/'))
}

fn default_path(url: &Url) -> &str {
    let path = url.path();
    if path.is_empty() || !path.starts_with('/') {
        "/"
    } else if let Some(index) = path.rfind('/') {
        if index == 0 { "/" } else { &path[..index] }
    } else {
        "/"
    }
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

#[allow(dead_code)]
fn _keep_cookie_imports_alive(cookie: &Cookie<'_>) -> Option<SameSite> {
    cookie.same_site()
}
