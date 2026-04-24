const CHROME_CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

const CHROME_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "rsa_pss_rsae_sha256:",
    "rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "rsa_pss_rsae_sha384:",
    "rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:",
    "rsa_pkcs1_sha512"
);

const FIREFOX_SIGALGS_FULL: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "ecdsa_secp521r1_sha512:",
    "rsa_pss_rsae_sha256:",
    "rsa_pss_rsae_sha384:",
    "rsa_pss_rsae_sha512:",
    "rsa_pkcs1_sha256:",
    "rsa_pkcs1_sha384:",
    "rsa_pkcs1_sha512:",
    "ecdsa_sha1:",
    "rsa_pkcs1_sha1"
);

const FIREFOX_SIGALGS_NO_ECDSA_SHA1: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "ecdsa_secp521r1_sha512:",
    "rsa_pss_rsae_sha256:",
    "rsa_pss_rsae_sha384:",
    "rsa_pss_rsae_sha512:",
    "rsa_pkcs1_sha256:",
    "rsa_pkcs1_sha384:",
    "rsa_pkcs1_sha512:",
    "rsa_pkcs1_sha1"
);

const FIREFOX_DELEGATED_CREDS_FULL: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "ecdsa_secp521r1_sha512:",
    "ecdsa_sha1"
);

const FIREFOX_DELEGATED_CREDS_MODERN: &str =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512";

const FIREFOX_CIPHER_LIST_CLASSIC: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

const SAFARI_CIPHER_LIST_CLASSIC: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
);

const SAFARI_CIPHER_LIST_MODERN: &str = concat!(
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
);

const OKHTTP_CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

const CHROME_CURVES_CLASSIC: &str = "X25519:P-256:P-384";
const CHROME_CURVES_KYBER_DRAFT: &str = "X25519Kyber768Draft00:X25519:P-256:P-384";
const CHROME_CURVES_MLKEM: &str = "X25519MLKEM768:X25519:P-256:P-384";
const FIREFOX_CURVES_CLASSIC: &str = "X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072";
const FIREFOX_CURVES_MLKEM: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072";
const SAFARI_CURVES_CLASSIC: &str = "X25519:P-256:P-384:P-521";
const SAFARI_CURVES_MLKEM: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";
const OKHTTP_CURVES: &str = "X25519:P-256:P-384";

const CHROME_CERT_COMPRESSION: &[CompressionAlgorithm] = &[CompressionAlgorithm::Brotli];
const FIREFOX_CERT_COMPRESSION: &[CompressionAlgorithm] = &[
    CompressionAlgorithm::Zlib,
    CompressionAlgorithm::Brotli,
    CompressionAlgorithm::Zstd,
];
const SAFARI_CERT_COMPRESSION: &[CompressionAlgorithm] = &[CompressionAlgorithm::Zlib];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientProfile {
    Chrome103,
    Chrome104,
    Chrome105,
    Chrome106,
    Chrome107,
    Chrome108,
    Chrome109,
    Chrome110,
    Chrome111,
    Chrome112,
    Chrome116Psk,
    Chrome116PskPq,
    Chrome117,
    Chrome120,
    Chrome124,
    Chrome130Psk,
    Chrome131,
    Chrome131Psk,
    Chrome133,
    Chrome133Psk,
    Chrome144,
    Chrome144Psk,
    Chrome146,
    Chrome146Psk,
    Brave146,
    Brave146Psk,
    Firefox102,
    Firefox104,
    Firefox105,
    Firefox106,
    Firefox108,
    Firefox110,
    Firefox117,
    Firefox120,
    Firefox123,
    Firefox132,
    Firefox133,
    Firefox135,
    Firefox146Psk,
    Firefox147,
    Firefox147Psk,
    Firefox148,
    Opera89,
    Opera90,
    Opera91,
    Safari15_6_1,
    Safari16,
    SafariIpad15_6,
    SafariIos15_5,
    SafariIos15_6,
    SafariIos16_0,
    SafariIos17_0,
    SafariIos18_0,
    Safari18_5,
    SafariIos26,
    ZalandoAndroidMobile,
    ZalandoIosMobile,
    NikeIosMobile,
    NikeAndroidMobile,
    Cloudscraper,
    MmsIos,
    MmsIos2,
    MmsIos3,
    MeshIos,
    MeshIos2,
    MeshAndroid,
    MeshAndroid2,
    ConfirmedIos,
    ConfirmedAndroid,
    OkHttp4Android7,
    OkHttp4Android8,
    OkHttp4Android9,
    OkHttp4Android10,
    OkHttp4Android11,
    OkHttp4Android12,
    OkHttp4Android13,
}

pub const DEFAULT_CLIENT_PROFILE: ClientProfile = ClientProfile::Chrome133;

const PROFILE_REGISTRY: &[(&str, ClientProfile)] = &[
    ("chrome_103", ClientProfile::Chrome103),
    ("chrome_104", ClientProfile::Chrome104),
    ("chrome_105", ClientProfile::Chrome105),
    ("chrome_106", ClientProfile::Chrome106),
    ("chrome_107", ClientProfile::Chrome107),
    ("chrome_108", ClientProfile::Chrome108),
    ("chrome_109", ClientProfile::Chrome109),
    ("chrome_110", ClientProfile::Chrome110),
    ("chrome_111", ClientProfile::Chrome111),
    ("chrome_112", ClientProfile::Chrome112),
    ("chrome_116_PSK", ClientProfile::Chrome116Psk),
    ("chrome_116_PSK_PQ", ClientProfile::Chrome116PskPq),
    ("chrome_117", ClientProfile::Chrome117),
    ("chrome_120", ClientProfile::Chrome120),
    ("chrome_124", ClientProfile::Chrome124),
    ("chrome_130_PSK", ClientProfile::Chrome130Psk),
    ("chrome_131", ClientProfile::Chrome131),
    ("chrome_131_PSK", ClientProfile::Chrome131Psk),
    ("chrome_133", ClientProfile::Chrome133),
    ("chrome_133_PSK", ClientProfile::Chrome133Psk),
    ("chrome_144", ClientProfile::Chrome144),
    ("chrome_144_PSK", ClientProfile::Chrome144Psk),
    ("chrome_146", ClientProfile::Chrome146),
    ("chrome_146_PSK", ClientProfile::Chrome146Psk),
    ("brave_146", ClientProfile::Brave146),
    ("brave_146_PSK", ClientProfile::Brave146Psk),
    ("firefox_102", ClientProfile::Firefox102),
    ("firefox_104", ClientProfile::Firefox104),
    ("firefox_105", ClientProfile::Firefox105),
    ("firefox_106", ClientProfile::Firefox106),
    ("firefox_108", ClientProfile::Firefox108),
    ("firefox_110", ClientProfile::Firefox110),
    ("firefox_117", ClientProfile::Firefox117),
    ("firefox_120", ClientProfile::Firefox120),
    ("firefox_123", ClientProfile::Firefox123),
    ("firefox_132", ClientProfile::Firefox132),
    ("firefox_133", ClientProfile::Firefox133),
    ("firefox_135", ClientProfile::Firefox135),
    ("firefox_146_PSK", ClientProfile::Firefox146Psk),
    ("firefox_147", ClientProfile::Firefox147),
    ("firefox_147_PSK", ClientProfile::Firefox147Psk),
    ("firefox_148", ClientProfile::Firefox148),
    ("opera_89", ClientProfile::Opera89),
    ("opera_90", ClientProfile::Opera90),
    ("opera_91", ClientProfile::Opera91),
    ("safari_15_6_1", ClientProfile::Safari15_6_1),
    ("safari_16_0", ClientProfile::Safari16),
    ("safari_ipad_15_6", ClientProfile::SafariIpad15_6),
    ("safari_ios_15_5", ClientProfile::SafariIos15_5),
    ("safari_ios_15_6", ClientProfile::SafariIos15_6),
    ("safari_ios_16_0", ClientProfile::SafariIos16_0),
    ("safari_ios_17_0", ClientProfile::SafariIos17_0),
    ("safari_ios_18_0", ClientProfile::SafariIos18_0),
    ("safari_ios_18_5", ClientProfile::Safari18_5),
    ("safari_ios_26_0", ClientProfile::SafariIos26),
    (
        "zalando_android_mobile",
        ClientProfile::ZalandoAndroidMobile,
    ),
    ("zalando_ios_mobile", ClientProfile::ZalandoIosMobile),
    ("nike_ios_mobile", ClientProfile::NikeIosMobile),
    ("nike_android_mobile", ClientProfile::NikeAndroidMobile),
    ("cloudscraper", ClientProfile::Cloudscraper),
    ("mms_ios", ClientProfile::MmsIos),
    ("mms_ios_1", ClientProfile::MmsIos),
    ("mms_ios_2", ClientProfile::MmsIos2),
    ("mms_ios_3", ClientProfile::MmsIos3),
    ("mesh_ios", ClientProfile::MeshIos),
    ("mesh_ios_1", ClientProfile::MeshIos),
    ("mesh_ios_2", ClientProfile::MeshIos2),
    ("mesh_android", ClientProfile::MeshAndroid),
    ("mesh_android_1", ClientProfile::MeshAndroid),
    ("mesh_android_2", ClientProfile::MeshAndroid2),
    ("confirmed_ios", ClientProfile::ConfirmedIos),
    ("confirmed_android", ClientProfile::ConfirmedAndroid),
    ("okhttp4_android_7", ClientProfile::OkHttp4Android7),
    ("okhttp4_android_8", ClientProfile::OkHttp4Android8),
    ("okhttp4_android_9", ClientProfile::OkHttp4Android9),
    ("okhttp4_android_10", ClientProfile::OkHttp4Android10),
    ("okhttp4_android_11", ClientProfile::OkHttp4Android11),
    ("okhttp4_android_12", ClientProfile::OkHttp4Android12),
    ("okhttp4_android_13", ClientProfile::OkHttp4Android13),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TlsProfileVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApplicationProtocol {
    Http1,
    Http2,
    Http3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApplicationSettingsProtocol {
    Http2,
    Http3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompressionAlgorithm {
    Brotli,
    Zlib,
    Zstd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudoHeader {
    Method,
    Authority,
    Scheme,
    Path,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Http2SettingId {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    Raw(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Http2Setting {
    pub id: Http2SettingId,
    pub value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeaderPrioritySpec {
    pub stream_dependency: u32,
    pub exclusive: bool,
    pub weight: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PriorityFrameSpec {
    pub stream_id: u32,
    pub stream_dependency: u32,
    pub exclusive: bool,
    pub weight: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Http3Setting {
    pub id: u64,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsProfileSpec {
    pub curves: &'static str,
    pub cipher_list: &'static str,
    pub sigalgs: &'static str,
    pub delegated_credentials: Option<&'static str>,
    pub alpn: Vec<ApplicationProtocol>,
    pub alps: Vec<ApplicationSettingsProtocol>,
    pub alps_use_new_codepoint: bool,
    pub grease_enabled: bool,
    pub session_ticket: bool,
    pub pre_shared_key: bool,
    pub psk_skip_session_ticket: bool,
    pub psk_dhe_ke: bool,
    pub enable_ocsp_stapling: bool,
    pub enable_signed_cert_timestamps: bool,
    pub enable_ech_grease: bool,
    pub renegotiation: bool,
    pub key_shares_limit: Option<u8>,
    pub certificate_compression: Vec<CompressionAlgorithm>,
    pub extension_order: Vec<u16>,
    pub include_padding: bool,
    pub permute_extensions: bool,
    pub preserve_tls13_cipher_list: bool,
    pub aes_hw_override: bool,
    pub record_size_limit: Option<u32>,
    pub min_tls_version: TlsProfileVersion,
    pub max_tls_version: TlsProfileVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http2ProfileSpec {
    pub settings: Vec<Http2Setting>,
    pub settings_order: Vec<Http2SettingId>,
    pub pseudo_header_order: Vec<PseudoHeader>,
    pub connection_flow: u32,
    pub stream_id: Option<u32>,
    pub allow_http: bool,
    pub header_priority: Option<HeaderPrioritySpec>,
    pub priorities: Vec<PriorityFrameSpec>,
    pub max_send_buffer_size: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http3ProfileSpec {
    pub settings: Vec<Http3Setting>,
    pub settings_order: Vec<u64>,
    pub pseudo_header_order: Vec<PseudoHeader>,
    pub priority_param: u32,
    pub send_grease_frames: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileSpec {
    pub key: &'static str,
    pub tls: TlsProfileSpec,
    pub http2: Http2ProfileSpec,
    pub http3: Option<Http3ProfileSpec>,
}

#[derive(Clone, Copy)]
struct ChromeSpec {
    curves: &'static str,
    alpn: &'static [ApplicationProtocol],
    alps: &'static [ApplicationSettingsProtocol],
    alps_use_new_codepoint: bool,
    enable_ech_grease: bool,
    pre_shared_key: bool,
    include_padding: bool,
    permute_extensions: bool,
    extension_order: &'static [u16],
    header_table_size: u32,
    enable_push: Option<bool>,
    max_concurrent_streams: Option<u32>,
    initial_window_size: u32,
    initial_connection_window_size: u32,
}

#[derive(Clone, Copy)]
struct FirefoxSpec {
    cipher_list: &'static str,
    curves: &'static str,
    sigalgs: &'static str,
    delegated_credentials: &'static str,
    session_ticket: bool,
    pre_shared_key: bool,
    psk_skip_session_ticket: bool,
    psk_dhe_ke: bool,
    enable_ech_grease: bool,
    enable_signed_cert_timestamps: bool,
    key_shares_limit: Option<u8>,
    cert_compression: Option<&'static [CompressionAlgorithm]>,
    extension_order: &'static [u16],
    header_table_size: u32,
    enable_push: Option<bool>,
    initial_stream_id: Option<u32>,
    initial_window_size: u32,
    initial_connection_window_size: u32,
    headers_dependency_stream_id: u32,
    headers_dependency_weight: u8,
    send_priorities: bool,
}

#[derive(Clone, Copy)]
struct SafariSpec {
    cipher_list: &'static str,
    curves: &'static str,
    sigalgs: &'static str,
    extension_order: &'static [u16],
    settings: &'static [Http2Setting],
    settings_order: &'static [Http2SettingId],
    pseudo_header_order: &'static [PseudoHeader],
    connection_flow: u32,
    header_priority: Option<HeaderPrioritySpec>,
}

impl Default for ClientProfile {
    fn default() -> Self {
        DEFAULT_CLIENT_PROFILE
    }
}

impl ClientProfile {
    pub const fn as_key(self) -> &'static str {
        match self {
            Self::Chrome105 => "chrome_105",
            Self::Chrome103 => "chrome_103",
            Self::Chrome104 => "chrome_104",
            Self::Chrome106 => "chrome_106",
            Self::Chrome107 => "chrome_107",
            Self::Chrome108 => "chrome_108",
            Self::Chrome109 => "chrome_109",
            Self::Chrome110 => "chrome_110",
            Self::Chrome111 => "chrome_111",
            Self::Chrome112 => "chrome_112",
            Self::Chrome116Psk => "chrome_116_PSK",
            Self::Chrome116PskPq => "chrome_116_PSK_PQ",
            Self::Chrome117 => "chrome_117",
            Self::Chrome120 => "chrome_120",
            Self::Chrome124 => "chrome_124",
            Self::Chrome130Psk => "chrome_130_PSK",
            Self::Chrome131 => "chrome_131",
            Self::Chrome131Psk => "chrome_131_PSK",
            Self::Chrome133 => "chrome_133",
            Self::Chrome133Psk => "chrome_133_PSK",
            Self::Chrome144 => "chrome_144",
            Self::Chrome144Psk => "chrome_144_PSK",
            Self::Chrome146 => "chrome_146",
            Self::Chrome146Psk => "chrome_146_PSK",
            Self::Brave146 => "brave_146",
            Self::Brave146Psk => "brave_146_PSK",
            Self::Firefox102 => "firefox_102",
            Self::Firefox104 => "firefox_104",
            Self::Firefox105 => "firefox_105",
            Self::Firefox106 => "firefox_106",
            Self::Firefox108 => "firefox_108",
            Self::Firefox110 => "firefox_110",
            Self::Firefox117 => "firefox_117",
            Self::Firefox120 => "firefox_120",
            Self::Firefox123 => "firefox_123",
            Self::Firefox132 => "firefox_132",
            Self::Firefox133 => "firefox_133",
            Self::Firefox135 => "firefox_135",
            Self::Firefox146Psk => "firefox_146_PSK",
            Self::Firefox147 => "firefox_147",
            Self::Firefox147Psk => "firefox_147_PSK",
            Self::Firefox148 => "firefox_148",
            Self::Opera89 => "opera_89",
            Self::Opera90 => "opera_90",
            Self::Opera91 => "opera_91",
            Self::Safari15_6_1 => "safari_15_6_1",
            Self::Safari16 => "safari_16_0",
            Self::SafariIpad15_6 => "safari_ipad_15_6",
            Self::SafariIos15_5 => "safari_ios_15_5",
            Self::SafariIos15_6 => "safari_ios_15_6",
            Self::SafariIos16_0 => "safari_ios_16_0",
            Self::SafariIos17_0 => "safari_ios_17_0",
            Self::SafariIos18_0 => "safari_ios_18_0",
            Self::Safari18_5 => "safari_ios_18_5",
            Self::SafariIos26 => "safari_ios_26_0",
            Self::ZalandoAndroidMobile => "zalando_android_mobile",
            Self::ZalandoIosMobile => "zalando_ios_mobile",
            Self::NikeIosMobile => "nike_ios_mobile",
            Self::NikeAndroidMobile => "nike_android_mobile",
            Self::Cloudscraper => "cloudscraper",
            Self::MmsIos => "mms_ios",
            Self::MmsIos2 => "mms_ios_2",
            Self::MmsIos3 => "mms_ios_3",
            Self::MeshIos => "mesh_ios",
            Self::MeshIos2 => "mesh_ios_2",
            Self::MeshAndroid => "mesh_android",
            Self::MeshAndroid2 => "mesh_android_2",
            Self::ConfirmedIos => "confirmed_ios",
            Self::ConfirmedAndroid => "confirmed_android",
            Self::OkHttp4Android7 => "okhttp4_android_7",
            Self::OkHttp4Android8 => "okhttp4_android_8",
            Self::OkHttp4Android9 => "okhttp4_android_9",
            Self::OkHttp4Android10 => "okhttp4_android_10",
            Self::OkHttp4Android11 => "okhttp4_android_11",
            Self::OkHttp4Android12 => "okhttp4_android_12",
            Self::OkHttp4Android13 => "okhttp4_android_13",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        PROFILE_REGISTRY
            .iter()
            .find_map(|(name, profile)| (*name == key).then_some(*profile))
    }

    pub fn registry() -> &'static [(&'static str, ClientProfile)] {
        PROFILE_REGISTRY
    }

    pub fn spec(self) -> Result<ProfileSpec, &'static str> {
        Ok(match self {
            Self::Chrome103 => chrome_103_spec(),
            Self::Chrome104 => chrome_104_spec(),
            Self::Chrome105 => chrome_105_spec(),
            Self::Chrome106 => chrome_106_spec(),
            Self::Chrome107 => chrome_107_spec(),
            Self::Chrome108 => chrome_108_spec(),
            Self::Chrome109 => chrome_109_spec(),
            Self::Chrome110 => chrome_110_spec(),
            Self::Chrome111 => chrome_111_spec(),
            Self::Chrome112 => chrome_112_spec(),
            Self::Chrome116Psk => chrome_116_psk_spec(),
            Self::Chrome116PskPq => chrome_116_psk_pq_spec(),
            Self::Chrome117 => chrome_117_spec(),
            Self::Chrome120 => chrome_120_spec(),
            Self::Chrome124 => chrome_124_spec(),
            Self::Chrome130Psk => chrome_130_psk_spec(),
            Self::Chrome131 => chrome_131_spec(),
            Self::Chrome131Psk => chrome_131_psk_spec(),
            Self::Chrome133 => chrome_133_spec(),
            Self::Chrome133Psk => chrome_133_psk_spec(),
            Self::Chrome144 => chrome_144_spec(),
            Self::Chrome144Psk => chrome_144_psk_spec(),
            Self::Chrome146 => chrome_146_spec(),
            Self::Chrome146Psk => chrome_146_psk_spec(),
            Self::Brave146 => brave_146_spec(),
            Self::Brave146Psk => brave_146_psk_spec(),
            Self::Firefox102 => firefox_102_spec(),
            Self::Firefox104 => firefox_104_spec(),
            Self::Firefox105 => firefox_105_spec(),
            Self::Firefox106 => firefox_106_spec(),
            Self::Firefox108 => firefox_108_spec(),
            Self::Firefox110 => firefox_110_spec(),
            Self::Firefox117 => firefox_117_spec(),
            Self::Firefox120 => firefox_120_spec(),
            Self::Firefox123 => firefox_123_spec(),
            Self::Firefox132 => firefox_132_spec(),
            Self::Firefox133 => firefox_133_spec(),
            Self::Firefox135 => firefox_135_spec(),
            Self::Firefox146Psk => firefox_146_psk_spec(),
            Self::Firefox147 => firefox_147_spec(),
            Self::Firefox147Psk => firefox_147_psk_spec(),
            Self::Firefox148 => firefox_148_spec(),
            Self::Opera89 => opera_89_spec(),
            Self::Opera90 => opera_90_spec(),
            Self::Opera91 => opera_91_spec(),
            Self::Safari15_6_1 => safari_15_6_1_spec(),
            Self::Safari16 => safari_16_spec(),
            Self::SafariIpad15_6 => safari_ipad_15_6_spec(),
            Self::SafariIos15_5 => safari_ios_15_5_spec(),
            Self::SafariIos15_6 => safari_ios_15_6_spec(),
            Self::SafariIos16_0 => safari_ios_16_0_spec(),
            Self::SafariIos17_0 => safari_ios_17_0_spec(),
            Self::SafariIos18_0 => safari_ios_18_0_spec(),
            Self::Safari18_5 => safari_ios_18_5_spec(),
            Self::SafariIos26 => safari_ios_26_spec(),
            Self::ZalandoAndroidMobile => zalando_android_mobile_spec(),
            Self::ZalandoIosMobile => zalando_ios_mobile_spec(),
            Self::NikeIosMobile => nike_ios_mobile_spec(),
            Self::NikeAndroidMobile => nike_android_mobile_spec(),
            Self::Cloudscraper => cloudscraper_spec(),
            Self::MmsIos => mms_ios_spec(),
            Self::MmsIos2 => mms_ios_2_spec(),
            Self::MmsIos3 => mms_ios_3_spec(),
            Self::MeshIos => mesh_ios_spec(),
            Self::MeshIos2 => mesh_ios_2_spec(),
            Self::MeshAndroid => mesh_android_spec(),
            Self::MeshAndroid2 => mesh_android_2_spec(),
            Self::ConfirmedIos => confirmed_ios_spec(),
            Self::ConfirmedAndroid => confirmed_android_spec(),
            Self::OkHttp4Android7 => okhttp_android_7_spec(),
            Self::OkHttp4Android8 => okhttp_android_8_spec(),
            Self::OkHttp4Android9 => okhttp_android_9_spec(),
            Self::OkHttp4Android10 => okhttp_android_10_spec(),
            Self::OkHttp4Android11 => okhttp_android_11_spec(),
            Self::OkHttp4Android12 => okhttp_android_12_spec(),
            Self::OkHttp4Android13 => okhttp_android_13_spec(),
        })
    }
}

fn chrome_103_spec() -> ProfileSpec {
    chrome_105_spec_with_key("chrome_103")
}

fn chrome_104_spec() -> ProfileSpec {
    chrome_105_spec_with_key("chrome_104")
}

fn chrome_105_spec() -> ProfileSpec {
    chrome_105_spec_with_key("chrome_105")
}

fn chrome_105_spec_with_key(key: &'static str) -> ProfileSpec {
    chrome_profile_spec(
        key,
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
            ],
            header_table_size: 65536,
            enable_push: None,
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_106_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_106",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_107_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_107",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_117_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_117",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                45, 0, 16, 13, 43, 17513, 10, 23, 35, 27, 18, 5, 51, 65281, 11, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_120_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_120",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: true,
            pre_shared_key: false,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                0, 45, 43, 5, 23, 35, 13, 65281, 16, 65037, 18, 51, 10, 11, 17513, 27,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_124_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_124",
        ChromeSpec {
            curves: CHROME_CURVES_KYBER_DRAFT,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: true,
            pre_shared_key: false,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                27, 18, 23, 17513, 16, 43, 13, 11, 0, 35, 10, 65037, 5, 65281, 45, 51,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_131_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_131",
        ChromeSpec {
            curves: CHROME_CURVES_MLKEM,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: true,
            pre_shared_key: false,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                13, 65037, 65281, 18, 27, 16, 5, 10, 17513, 11, 51, 35, 43, 45, 0, 23,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_133_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_133",
        ChromeSpec {
            curves: CHROME_CURVES_MLKEM,
            alpn: &[
                ApplicationProtocol::Http3,
                ApplicationProtocol::Http2,
                ApplicationProtocol::Http1,
            ],
            alps: &[
                ApplicationSettingsProtocol::Http3,
                ApplicationSettingsProtocol::Http2,
            ],
            alps_use_new_codepoint: true,
            enable_ech_grease: true,
            pre_shared_key: false,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                35, 13, 17613, 51, 18, 11, 43, 5, 16, 0, 65037, 27, 10, 45, 23, 65281,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        Some(chrome_h3_spec()),
    )
}

fn chrome_144_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_144",
        ChromeSpec {
            curves: CHROME_CURVES_MLKEM,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: true,
            enable_ech_grease: true,
            pre_shared_key: false,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                51, 0, 17613, 65281, 10, 27, 35, 5, 23, 43, 13, 18, 11, 65037, 16, 45,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        Some(chrome_h3_spec()),
    )
}

fn chrome_108_spec() -> ProfileSpec {
    chrome_107_spec_with_key("chrome_108")
}

fn chrome_109_spec() -> ProfileSpec {
    chrome_107_spec_with_key("chrome_109")
}

fn chrome_107_spec_with_key(key: &'static str) -> ProfileSpec {
    chrome_profile_spec(
        key,
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_110_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_110",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                23, 27, 18, 51, 17513, 0, 16, 35, 11, 5, 65281, 43, 13, 45, 10, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_111_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_111",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                27, 11, 17513, 5, 10, 18, 23, 0, 45, 51, 43, 35, 65281, 16, 13, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_112_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_112",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                45, 51, 17513, 43, 0, 11, 5, 23, 16, 10, 65281, 27, 18, 35, 13, 21,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_116_psk_spec() -> ProfileSpec {
    with_chrome_psk_metadata(chrome_112_spec(), "chrome_116_PSK")
}

fn chrome_116_psk_pq_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_116_PSK_PQ",
        ChromeSpec {
            curves: CHROME_CURVES_KYBER_DRAFT,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: true,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_130_psk_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_130_PSK",
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: true,
            pre_shared_key: true,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                13, 65037, 65281, 18, 27, 16, 5, 10, 17513, 11, 51, 35, 43, 45, 0, 23,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn chrome_131_psk_spec() -> ProfileSpec {
    with_chrome_psk_metadata(chrome_131_spec(), "chrome_131_PSK")
}

fn chrome_133_psk_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_133_PSK",
        ChromeSpec {
            curves: CHROME_CURVES_MLKEM,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: true,
            enable_ech_grease: true,
            pre_shared_key: true,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                18, 0, 65037, 65281, 23, 5, 11, 35, 17613, 51, 13, 10, 16, 43, 45, 27,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        Some(chrome_h3_spec()),
    )
}

fn chrome_144_psk_spec() -> ProfileSpec {
    chrome_profile_spec(
        "chrome_144_PSK",
        ChromeSpec {
            curves: CHROME_CURVES_MLKEM,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: true,
            enable_ech_grease: true,
            pre_shared_key: true,
            include_padding: false,
            permute_extensions: false,
            extension_order: &[
                17613, 43, 18, 65037, 51, 13, 10, 27, 23, 35, 0, 65281, 45, 11, 5, 16,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        Some(chrome_h3_spec()),
    )
}

fn chrome_146_spec() -> ProfileSpec {
    with_key(chrome_144_spec(), "chrome_146")
}

fn chrome_146_psk_spec() -> ProfileSpec {
    with_chrome_psk_metadata(chrome_144_spec(), "chrome_146_PSK")
}

fn brave_146_spec() -> ProfileSpec {
    let mut spec = with_key(chrome_144_spec(), "brave_146");
    spec.tls.permute_extensions = true;
    spec
}

fn brave_146_psk_spec() -> ProfileSpec {
    let mut spec = with_chrome_psk_metadata(chrome_144_spec(), "brave_146_PSK");
    spec.tls.permute_extensions = true;
    spec
}

fn firefox_117_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_117",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: true,
            pre_shared_key: true,
            psk_skip_session_ticket: true,
            psk_dhe_ke: true,
            enable_ech_grease: false,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(2),
            cert_compression: None,
            extension_order: &[0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
            header_table_size: 65536,
            enable_push: None,
            initial_stream_id: Some(15),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 13,
            headers_dependency_weight: 21,
            send_priorities: true,
        },
        None,
    )
}

fn firefox_120_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_120",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: false,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: false,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(2),
            cert_compression: None,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 28, 65037],
            header_table_size: 65536,
            enable_push: None,
            initial_stream_id: Some(15),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 13,
            headers_dependency_weight: 41,
            send_priorities: true,
        },
        None,
    )
}

fn firefox_123_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_123",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: true,
            pre_shared_key: true,
            psk_skip_session_ticket: true,
            psk_dhe_ke: true,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(2),
            cert_compression: None,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 65037,
            ],
            header_table_size: 65536,
            enable_push: None,
            initial_stream_id: Some(15),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 13,
            headers_dependency_weight: 41,
            send_priorities: true,
        },
        None,
    )
}

fn firefox_132_spec() -> ProfileSpec {
    let mut spec = firefox_profile_spec(
        "firefox_132",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: false,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: false,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(3),
            cert_compression: Some(FIREFOX_CERT_COMPRESSION),
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 28, 27, 65037],
            header_table_size: 65536,
            enable_push: Some(false),
            initial_stream_id: Some(3),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 0,
            headers_dependency_weight: 21,
            send_priorities: false,
        },
        None,
    );
    spec.http2.settings.push(Http2Setting {
        id: Http2SettingId::Raw(9),
        value: 1,
    });
    spec.http2.settings_order.push(Http2SettingId::Raw(9));
    spec
}

fn firefox_133_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_133",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: false,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: false,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(3),
            cert_compression: Some(FIREFOX_CERT_COMPRESSION),
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 28, 27, 65037],
            header_table_size: 65536,
            enable_push: Some(false),
            initial_stream_id: Some(3),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 0,
            headers_dependency_weight: 21,
            send_priorities: false,
        },
        None,
    )
}

fn firefox_105_spec() -> ProfileSpec {
    firefox_105_spec_with_key("firefox_105")
}

fn firefox_102_spec() -> ProfileSpec {
    firefox_105_spec_with_key("firefox_102")
}

fn firefox_104_spec() -> ProfileSpec {
    firefox_105_spec_with_key("firefox_104")
}

fn firefox_106_spec() -> ProfileSpec {
    firefox_105_spec_with_key("firefox_106")
}

fn firefox_108_spec() -> ProfileSpec {
    firefox_105_spec_with_key("firefox_108")
}

fn firefox_105_spec_with_key(key: &'static str) -> ProfileSpec {
    firefox_profile_spec(
        key,
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: true,
            pre_shared_key: true,
            psk_skip_session_ticket: true,
            psk_dhe_ke: true,
            enable_ech_grease: false,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(2),
            cert_compression: None,
            extension_order: &[0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
            header_table_size: 65536,
            enable_push: None,
            initial_stream_id: Some(15),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 13,
            headers_dependency_weight: 41,
            send_priorities: true,
        },
        None,
    )
}

fn firefox_110_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_110",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: false,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: false,
            enable_ech_grease: false,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(2),
            cert_compression: None,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 28, 21],
            header_table_size: 65536,
            enable_push: None,
            initial_stream_id: Some(15),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 13,
            headers_dependency_weight: 41,
            send_priorities: true,
        },
        None,
    )
}

fn firefox_135_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_135",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: false,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: false,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: true,
            key_shares_limit: Some(3),
            cert_compression: Some(FIREFOX_CERT_COMPRESSION),
            extension_order: &[
                0, 23, 65281, 10, 11, 16, 5, 34, 18, 51, 43, 13, 28, 27, 65037,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            initial_stream_id: Some(3),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 0,
            headers_dependency_weight: 21,
            send_priorities: false,
        },
        None,
    )
}

fn firefox_147_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_147",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_NO_ECDSA_SHA1,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_MODERN,
            session_ticket: true,
            pre_shared_key: true,
            psk_skip_session_ticket: true,
            psk_dhe_ke: true,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: true,
            key_shares_limit: Some(3),
            cert_compression: Some(FIREFOX_CERT_COMPRESSION),
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            initial_stream_id: Some(3),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 0,
            headers_dependency_weight: 21,
            send_priorities: false,
        },
        Some(firefox_147_h3_spec()),
    )
}

fn firefox_146_psk_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_146_PSK",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_FULL,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_FULL,
            session_ticket: false,
            pre_shared_key: true,
            psk_skip_session_ticket: true,
            psk_dhe_ke: true,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: true,
            key_shares_limit: Some(3),
            cert_compression: Some(FIREFOX_CERT_COMPRESSION),
            extension_order: &[
                0, 23, 65281, 10, 11, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            initial_stream_id: Some(3),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 0,
            headers_dependency_weight: 21,
            send_priorities: false,
        },
        Some(firefox_147_h3_spec()),
    )
}

fn firefox_147_psk_spec() -> ProfileSpec {
    firefox_profile_spec(
        "firefox_147_PSK",
        FirefoxSpec {
            cipher_list: FIREFOX_CIPHER_LIST_CLASSIC,
            curves: FIREFOX_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_NO_ECDSA_SHA1,
            delegated_credentials: FIREFOX_DELEGATED_CREDS_MODERN,
            session_ticket: false,
            pre_shared_key: true,
            psk_skip_session_ticket: true,
            psk_dhe_ke: true,
            enable_ech_grease: true,
            enable_signed_cert_timestamps: false,
            key_shares_limit: Some(3),
            cert_compression: Some(FIREFOX_CERT_COMPRESSION),
            extension_order: &[
                0, 23, 65281, 10, 11, 16, 5, 34, 51, 43, 13, 45, 28, 27, 65037,
            ],
            header_table_size: 65536,
            enable_push: Some(false),
            initial_stream_id: Some(3),
            initial_window_size: 131072,
            initial_connection_window_size: 12517377,
            headers_dependency_stream_id: 0,
            headers_dependency_weight: 21,
            send_priorities: false,
        },
        Some(firefox_147_h3_spec()),
    )
}

fn firefox_148_spec() -> ProfileSpec {
    with_key(firefox_147_spec(), "firefox_148")
}

fn opera_89_spec() -> ProfileSpec {
    opera_spec("opera_89")
}

fn opera_90_spec() -> ProfileSpec {
    opera_spec("opera_90")
}

fn opera_91_spec() -> ProfileSpec {
    opera_spec("opera_91")
}

fn opera_spec(key: &'static str) -> ProfileSpec {
    chrome_profile_spec(
        key,
        ChromeSpec {
            curves: CHROME_CURVES_CLASSIC,
            alpn: &[ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: &[ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            enable_ech_grease: false,
            pre_shared_key: false,
            include_padding: true,
            permute_extensions: false,
            extension_order: &[
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
            ],
            header_table_size: 65536,
            enable_push: None,
            max_concurrent_streams: Some(1000),
            initial_window_size: 6291456,
            initial_connection_window_size: 15663105,
        },
        None,
    )
}

fn safari_16_spec() -> ProfileSpec {
    safari_profile_spec(
        "safari_16_0",
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_CLASSIC,
            curves: SAFARI_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 4_194_304,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
            ],
            settings_order: &[
                Http2SettingId::InitialWindowSize,
                Http2SettingId::MaxConcurrentStreams,
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Path,
                PseudoHeader::Authority,
            ],
            connection_flow: 10_485_760,
            header_priority: None,
        },
    )
}

fn safari_15_6_1_spec() -> ProfileSpec {
    safari_profile_spec(
        "safari_15_6_1",
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_CLASSIC,
            curves: SAFARI_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 4_194_304,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
            ],
            settings_order: &[
                Http2SettingId::InitialWindowSize,
                Http2SettingId::MaxConcurrentStreams,
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Path,
                PseudoHeader::Authority,
            ],
            connection_flow: 10_485_760,
            header_priority: None,
        },
    )
}

fn safari_ipad_15_6_spec() -> ProfileSpec {
    safari_old_ios_profile_spec("safari_ipad_15_6")
}

fn safari_ios_15_5_spec() -> ProfileSpec {
    safari_old_ios_profile_spec("safari_ios_15_5")
}

fn safari_ios_15_6_spec() -> ProfileSpec {
    safari_old_ios_profile_spec("safari_ios_15_6")
}

fn safari_ios_16_0_spec() -> ProfileSpec {
    safari_old_ios_profile_spec("safari_ios_16_0")
}

fn safari_ios_17_0_spec() -> ProfileSpec {
    safari_profile_spec(
        "safari_ios_17_0",
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_CLASSIC,
            curves: SAFARI_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::EnablePush,
                    value: 0,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 2_097_152,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
            ],
            settings_order: &[
                Http2SettingId::EnablePush,
                Http2SettingId::InitialWindowSize,
                Http2SettingId::MaxConcurrentStreams,
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Path,
                PseudoHeader::Authority,
            ],
            connection_flow: 10_485_760,
            header_priority: None,
        },
    )
}

fn safari_ios_18_0_spec() -> ProfileSpec {
    safari_profile_spec(
        "safari_ios_18_0",
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_CLASSIC,
            curves: SAFARI_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::EnablePush,
                    value: 0,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 2_097_152,
                },
                Http2Setting {
                    id: Http2SettingId::Raw(8),
                    value: 1,
                },
                Http2Setting {
                    id: Http2SettingId::Raw(9),
                    value: 1,
                },
            ],
            settings_order: &[
                Http2SettingId::EnablePush,
                Http2SettingId::MaxConcurrentStreams,
                Http2SettingId::InitialWindowSize,
                Http2SettingId::Raw(8),
                Http2SettingId::Raw(9),
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ],
            connection_flow: 10_420_225,
            header_priority: None,
        },
    )
}

fn safari_old_ios_profile_spec(key: &'static str) -> ProfileSpec {
    safari_profile_spec(
        key,
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_CLASSIC,
            curves: SAFARI_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_FULL,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 2_097_152,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
            ],
            settings_order: &[
                Http2SettingId::InitialWindowSize,
                Http2SettingId::MaxConcurrentStreams,
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Path,
                PseudoHeader::Authority,
            ],
            connection_flow: 10_485_760,
            header_priority: None,
        },
    )
}

fn safari_ios_18_5_spec() -> ProfileSpec {
    safari_profile_spec(
        "safari_ios_18_5",
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_CLASSIC,
            curves: SAFARI_CURVES_CLASSIC,
            sigalgs: FIREFOX_SIGALGS_NO_ECDSA_SHA1,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::EnablePush,
                    value: 0,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 2_097_152,
                },
                Http2Setting {
                    id: Http2SettingId::Raw(9),
                    value: 1,
                },
            ],
            settings_order: &[
                Http2SettingId::EnablePush,
                Http2SettingId::MaxConcurrentStreams,
                Http2SettingId::InitialWindowSize,
                Http2SettingId::Raw(9),
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ],
            connection_flow: 10_420_225,
            header_priority: Some(HeaderPrioritySpec {
                stream_dependency: 0,
                exclusive: false,
                weight: 255,
            }),
        },
    )
}

fn safari_ios_26_spec() -> ProfileSpec {
    safari_profile_spec(
        "safari_ios_26_0",
        SafariSpec {
            cipher_list: SAFARI_CIPHER_LIST_MODERN,
            curves: SAFARI_CURVES_MLKEM,
            sigalgs: FIREFOX_SIGALGS_NO_ECDSA_SHA1,
            extension_order: &[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27],
            settings: &[
                Http2Setting {
                    id: Http2SettingId::EnablePush,
                    value: 0,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 2_097_152,
                },
                Http2Setting {
                    id: Http2SettingId::Raw(9),
                    value: 1,
                },
            ],
            settings_order: &[
                Http2SettingId::EnablePush,
                Http2SettingId::MaxConcurrentStreams,
                Http2SettingId::InitialWindowSize,
                Http2SettingId::Raw(9),
            ],
            pseudo_header_order: &[
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ],
            connection_flow: 10_420_225,
            header_priority: None,
        },
    )
}

fn zalando_android_mobile_spec() -> ProfileSpec {
    android_custom_large_window_spec("zalando_android_mobile")
}

fn zalando_ios_mobile_spec() -> ProfileSpec {
    ios_custom_h2_spec("zalando_ios_mobile")
}

fn nike_ios_mobile_spec() -> ProfileSpec {
    ios_custom_h2_spec("nike_ios_mobile")
}

fn nike_android_mobile_spec() -> ProfileSpec {
    android_custom_large_window_spec("nike_android_mobile")
}

fn cloudscraper_spec() -> ProfileSpec {
    let mut spec = with_key(okhttp_android_10_spec(), "cloudscraper");
    spec.tls.alpn = vec![ApplicationProtocol::Http1];
    spec.tls.enable_signed_cert_timestamps = false;
    spec
}

fn mms_ios_spec() -> ProfileSpec {
    ios_custom_h2_spec("mms_ios")
}

fn mms_ios_2_spec() -> ProfileSpec {
    ios_custom_h2_spec("mms_ios_2")
}

fn mms_ios_3_spec() -> ProfileSpec {
    ios_custom_h2_spec("mms_ios_3")
}

fn mesh_ios_spec() -> ProfileSpec {
    ios_custom_h2_spec("mesh_ios")
}

fn mesh_ios_2_spec() -> ProfileSpec {
    let mut spec = ios_custom_h2_spec("mesh_ios_2");
    spec.http2.pseudo_header_order = chrome_pseudo_header_model();
    spec
}

fn mesh_android_spec() -> ProfileSpec {
    with_key(chrome_133_spec(), "mesh_android")
}

fn mesh_android_2_spec() -> ProfileSpec {
    with_key(okhttp_android_9_spec(), "mesh_android_2")
}

fn confirmed_ios_spec() -> ProfileSpec {
    ios_custom_h2_spec("confirmed_ios")
}

fn confirmed_android_spec() -> ProfileSpec {
    with_key(okhttp_android_9_spec(), "confirmed_android")
}

fn okhttp_android_7_spec() -> ProfileSpec {
    with_key(
        okhttp_profile_spec("okhttp4_android_12"),
        "okhttp4_android_7",
    )
}

fn okhttp_android_8_spec() -> ProfileSpec {
    with_key(
        okhttp_profile_spec("okhttp4_android_12"),
        "okhttp4_android_8",
    )
}

fn okhttp_android_9_spec() -> ProfileSpec {
    with_key(
        okhttp_profile_spec("okhttp4_android_12"),
        "okhttp4_android_9",
    )
}

fn okhttp_android_10_spec() -> ProfileSpec {
    with_key(
        okhttp_profile_spec("okhttp4_android_12"),
        "okhttp4_android_10",
    )
}

fn okhttp_android_11_spec() -> ProfileSpec {
    with_key(
        okhttp_profile_spec("okhttp4_android_12"),
        "okhttp4_android_11",
    )
}

fn okhttp_android_12_spec() -> ProfileSpec {
    okhttp_profile_spec("okhttp4_android_12")
}

fn okhttp_android_13_spec() -> ProfileSpec {
    okhttp_profile_spec("okhttp4_android_13")
}

fn with_key(mut spec: ProfileSpec, key: &'static str) -> ProfileSpec {
    spec.key = key;
    spec
}

fn with_chrome_psk_metadata(mut spec: ProfileSpec, key: &'static str) -> ProfileSpec {
    spec.key = key;
    spec.tls.pre_shared_key = true;
    spec.tls.psk_skip_session_ticket = true;
    spec.tls.psk_dhe_ke = true;
    spec
}

fn ios_custom_h2_spec(key: &'static str) -> ProfileSpec {
    let mut spec = with_key(safari_ios_18_5_spec(), key);
    spec.http2.settings = vec![
        Http2Setting {
            id: Http2SettingId::HeaderTableSize,
            value: 4096,
        },
        Http2Setting {
            id: Http2SettingId::EnablePush,
            value: 1,
        },
        Http2Setting {
            id: Http2SettingId::MaxConcurrentStreams,
            value: 100,
        },
        Http2Setting {
            id: Http2SettingId::InitialWindowSize,
            value: 2_097_152,
        },
        Http2Setting {
            id: Http2SettingId::MaxFrameSize,
            value: 16_384,
        },
        Http2Setting {
            id: Http2SettingId::MaxHeaderListSize,
            value: u32::MAX,
        },
    ];
    spec.http2.settings_order = vec![
        Http2SettingId::HeaderTableSize,
        Http2SettingId::EnablePush,
        Http2SettingId::MaxConcurrentStreams,
        Http2SettingId::InitialWindowSize,
        Http2SettingId::MaxFrameSize,
        Http2SettingId::MaxHeaderListSize,
    ];
    spec.http2.pseudo_header_order = vec![
        PseudoHeader::Method,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
        PseudoHeader::Authority,
    ];
    spec.http2.connection_flow = 15_663_105;
    spec.http2.header_priority = None;
    spec
}

fn android_custom_large_window_spec(key: &'static str) -> ProfileSpec {
    let mut spec = with_key(okhttp_android_10_spec(), key);
    spec.http2.settings = vec![
        Http2Setting {
            id: Http2SettingId::HeaderTableSize,
            value: 4096,
        },
        Http2Setting {
            id: Http2SettingId::MaxConcurrentStreams,
            value: u32::MAX,
        },
        Http2Setting {
            id: Http2SettingId::InitialWindowSize,
            value: 16_777_216,
        },
        Http2Setting {
            id: Http2SettingId::MaxFrameSize,
            value: 16_384,
        },
        Http2Setting {
            id: Http2SettingId::MaxHeaderListSize,
            value: u32::MAX,
        },
    ];
    spec.http2.settings_order = vec![
        Http2SettingId::HeaderTableSize,
        Http2SettingId::MaxConcurrentStreams,
        Http2SettingId::InitialWindowSize,
        Http2SettingId::MaxFrameSize,
        Http2SettingId::MaxHeaderListSize,
    ];
    spec.http2.pseudo_header_order = vec![
        PseudoHeader::Method,
        PseudoHeader::Path,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
    ];
    spec.http2.connection_flow = 15_663_105;
    spec
}

fn chrome_profile_spec(
    key: &'static str,
    spec: ChromeSpec,
    http3: Option<Http3ProfileSpec>,
) -> ProfileSpec {
    let mut settings = vec![Http2Setting {
        id: Http2SettingId::HeaderTableSize,
        value: spec.header_table_size,
    }];
    let mut settings_order = vec![Http2SettingId::HeaderTableSize];

    if let Some(enable_push) = spec.enable_push {
        settings.push(Http2Setting {
            id: Http2SettingId::EnablePush,
            value: u32::from(enable_push),
        });
        settings_order.push(Http2SettingId::EnablePush);
    }

    if let Some(max_concurrent_streams) = spec.max_concurrent_streams {
        settings.push(Http2Setting {
            id: Http2SettingId::MaxConcurrentStreams,
            value: max_concurrent_streams,
        });
        settings_order.push(Http2SettingId::MaxConcurrentStreams);
    }

    settings.push(Http2Setting {
        id: Http2SettingId::InitialWindowSize,
        value: spec.initial_window_size,
    });
    settings.push(Http2Setting {
        id: Http2SettingId::MaxHeaderListSize,
        value: 262144,
    });
    settings_order.push(Http2SettingId::InitialWindowSize);
    settings_order.push(Http2SettingId::MaxHeaderListSize);

    ProfileSpec {
        key,
        tls: TlsProfileSpec {
            curves: spec.curves,
            cipher_list: CHROME_CIPHER_LIST,
            sigalgs: CHROME_SIGALGS,
            delegated_credentials: None,
            alpn: spec.alpn.to_vec(),
            alps: spec.alps.to_vec(),
            alps_use_new_codepoint: spec.alps_use_new_codepoint,
            grease_enabled: true,
            session_ticket: true,
            pre_shared_key: spec.pre_shared_key,
            psk_skip_session_ticket: false,
            psk_dhe_ke: true,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            enable_ech_grease: spec.enable_ech_grease,
            renegotiation: true,
            key_shares_limit: None,
            certificate_compression: CHROME_CERT_COMPRESSION.to_vec(),
            extension_order: spec.extension_order.to_vec(),
            include_padding: spec.include_padding,
            permute_extensions: spec.permute_extensions,
            preserve_tls13_cipher_list: true,
            aes_hw_override: true,
            record_size_limit: None,
            min_tls_version: TlsProfileVersion::Tls12,
            max_tls_version: TlsProfileVersion::Tls13,
        },
        http2: Http2ProfileSpec {
            settings,
            settings_order,
            pseudo_header_order: chrome_pseudo_header_model(),
            connection_flow: spec.initial_connection_window_size,
            stream_id: None,
            allow_http: false,
            header_priority: None,
            priorities: Vec::new(),
            max_send_buffer_size: Some(1_048_576),
        },
        http3,
    }
}

fn firefox_profile_spec(
    key: &'static str,
    spec: FirefoxSpec,
    http3: Option<Http3ProfileSpec>,
) -> ProfileSpec {
    let mut settings = vec![Http2Setting {
        id: Http2SettingId::HeaderTableSize,
        value: spec.header_table_size,
    }];
    let mut settings_order = vec![Http2SettingId::HeaderTableSize];

    if let Some(enable_push) = spec.enable_push {
        settings.push(Http2Setting {
            id: Http2SettingId::EnablePush,
            value: u32::from(enable_push),
        });
        settings_order.push(Http2SettingId::EnablePush);
    }

    settings.push(Http2Setting {
        id: Http2SettingId::InitialWindowSize,
        value: spec.initial_window_size,
    });
    settings.push(Http2Setting {
        id: Http2SettingId::MaxFrameSize,
        value: 16384,
    });
    settings_order.push(Http2SettingId::InitialWindowSize);
    settings_order.push(Http2SettingId::MaxFrameSize);

    ProfileSpec {
        key,
        tls: TlsProfileSpec {
            curves: spec.curves,
            cipher_list: spec.cipher_list,
            sigalgs: spec.sigalgs,
            delegated_credentials: Some(spec.delegated_credentials),
            alpn: vec![ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: Vec::new(),
            alps_use_new_codepoint: false,
            grease_enabled: false,
            session_ticket: spec.session_ticket,
            pre_shared_key: spec.pre_shared_key,
            psk_skip_session_ticket: spec.psk_skip_session_ticket,
            psk_dhe_ke: spec.psk_dhe_ke,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: spec.enable_signed_cert_timestamps,
            enable_ech_grease: spec.enable_ech_grease,
            renegotiation: false,
            key_shares_limit: spec.key_shares_limit,
            certificate_compression: spec.cert_compression.unwrap_or(&[]).to_vec(),
            extension_order: spec.extension_order.to_vec(),
            include_padding: false,
            permute_extensions: false,
            preserve_tls13_cipher_list: true,
            aes_hw_override: true,
            record_size_limit: Some(0x4001),
            min_tls_version: TlsProfileVersion::Tls12,
            max_tls_version: TlsProfileVersion::Tls13,
        },
        http2: Http2ProfileSpec {
            settings,
            settings_order,
            pseudo_header_order: firefox_pseudo_header_model(),
            connection_flow: spec.initial_connection_window_size,
            stream_id: spec.initial_stream_id,
            allow_http: false,
            header_priority: Some(HeaderPrioritySpec {
                stream_dependency: spec.headers_dependency_stream_id,
                exclusive: false,
                weight: spec.headers_dependency_weight,
            }),
            priorities: if spec.send_priorities {
                firefox_priority_frame_specs()
            } else {
                Vec::new()
            },
            max_send_buffer_size: None,
        },
        http3,
    }
}

fn safari_profile_spec(key: &'static str, spec: SafariSpec) -> ProfileSpec {
    ProfileSpec {
        key,
        tls: TlsProfileSpec {
            curves: spec.curves,
            cipher_list: spec.cipher_list,
            sigalgs: spec.sigalgs,
            delegated_credentials: None,
            alpn: vec![ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: Vec::new(),
            alps_use_new_codepoint: false,
            grease_enabled: true,
            session_ticket: false,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: true,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            enable_ech_grease: false,
            renegotiation: true,
            key_shares_limit: None,
            certificate_compression: SAFARI_CERT_COMPRESSION.to_vec(),
            extension_order: spec.extension_order.to_vec(),
            include_padding: spec.extension_order.contains(&21),
            permute_extensions: false,
            preserve_tls13_cipher_list: true,
            aes_hw_override: true,
            record_size_limit: None,
            min_tls_version: TlsProfileVersion::Tls12,
            max_tls_version: TlsProfileVersion::Tls13,
        },
        http2: Http2ProfileSpec {
            settings: spec.settings.to_vec(),
            settings_order: spec.settings_order.to_vec(),
            pseudo_header_order: spec.pseudo_header_order.to_vec(),
            connection_flow: spec.connection_flow,
            stream_id: None,
            allow_http: false,
            header_priority: spec.header_priority,
            priorities: Vec::new(),
            max_send_buffer_size: None,
        },
        http3: None,
    }
}

fn okhttp_profile_spec(key: &'static str) -> ProfileSpec {
    ProfileSpec {
        key,
        tls: TlsProfileSpec {
            curves: OKHTTP_CURVES,
            cipher_list: OKHTTP_CIPHER_LIST,
            sigalgs: FIREFOX_SIGALGS_NO_ECDSA_SHA1,
            delegated_credentials: None,
            alpn: vec![ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: Vec::new(),
            alps_use_new_codepoint: false,
            grease_enabled: false,
            session_ticket: true,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: true,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: false,
            enable_ech_grease: false,
            renegotiation: false,
            key_shares_limit: None,
            certificate_compression: Vec::new(),
            extension_order: vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 21],
            include_padding: true,
            permute_extensions: false,
            preserve_tls13_cipher_list: true,
            aes_hw_override: true,
            record_size_limit: None,
            min_tls_version: TlsProfileVersion::Tls12,
            max_tls_version: TlsProfileVersion::Tls13,
        },
        http2: Http2ProfileSpec {
            settings: vec![Http2Setting {
                id: Http2SettingId::InitialWindowSize,
                value: 16_777_216,
            }],
            settings_order: vec![Http2SettingId::InitialWindowSize],
            pseudo_header_order: vec![
                PseudoHeader::Method,
                PseudoHeader::Path,
                PseudoHeader::Authority,
                PseudoHeader::Scheme,
            ],
            connection_flow: 16_711_681,
            stream_id: None,
            allow_http: false,
            header_priority: None,
            priorities: Vec::new(),
            max_send_buffer_size: None,
        },
        http3: None,
    }
}

fn chrome_h3_spec() -> Http3ProfileSpec {
    Http3ProfileSpec {
        settings: vec![
            Http3Setting {
                id: 1,
                value: 65536,
            },
            Http3Setting { id: 7, value: 100 },
        ],
        settings_order: vec![1, 0x6, 7, 0x33],
        pseudo_header_order: chrome_pseudo_header_model(),
        priority_param: 984832,
        send_grease_frames: true,
    }
}

fn firefox_147_h3_spec() -> Http3ProfileSpec {
    Http3ProfileSpec {
        settings: vec![
            Http3Setting {
                id: 1,
                value: 65536,
            },
            Http3Setting { id: 7, value: 20 },
            Http3Setting {
                id: 727_725_890,
                value: 0,
            },
            Http3Setting {
                id: 16_765_559,
                value: 1,
            },
            Http3Setting { id: 0x33, value: 1 },
            Http3Setting { id: 8, value: 1 },
        ],
        settings_order: vec![1, 7, 727_725_890, 16_765_559, 0x33, 8],
        pseudo_header_order: vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Authority,
            PseudoHeader::Path,
        ],
        priority_param: 0,
        send_grease_frames: true,
    }
}

fn chrome_pseudo_header_model() -> Vec<PseudoHeader> {
    vec![
        PseudoHeader::Method,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
    ]
}

fn firefox_pseudo_header_model() -> Vec<PseudoHeader> {
    vec![
        PseudoHeader::Method,
        PseudoHeader::Path,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
    ]
}

fn firefox_priority_frame_specs() -> Vec<PriorityFrameSpec> {
    vec![
        PriorityFrameSpec {
            stream_id: 3,
            stream_dependency: 0,
            exclusive: false,
            weight: 200,
        },
        PriorityFrameSpec {
            stream_id: 5,
            stream_dependency: 0,
            exclusive: false,
            weight: 100,
        },
        PriorityFrameSpec {
            stream_id: 7,
            stream_dependency: 0,
            exclusive: false,
            weight: 0,
        },
        PriorityFrameSpec {
            stream_id: 9,
            stream_dependency: 7,
            exclusive: false,
            weight: 0,
        },
        PriorityFrameSpec {
            stream_id: 11,
            stream_dependency: 3,
            exclusive: false,
            weight: 0,
        },
        PriorityFrameSpec {
            stream_id: 13,
            stream_dependency: 0,
            exclusive: false,
            weight: 240,
        },
    ]
}
