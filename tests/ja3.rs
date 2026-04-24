use tls_rust::parse_ja3;

#[test]
fn parses_chrome_120_ja3() {
    let spec = parse_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-45-43-5-23-35-13-65281-16-65037-18-51-10-11-17513-27,29-23-24,0")
        .expect("should parse");
    assert_eq!(spec.cipher_suites.len(), 15);
    assert_eq!(spec.extensions.len(), 16);
}

#[test]
fn parses_chrome_112_psk_ja3() {
    let spec = parse_ja3("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-51-17513-43-0-11-5-23-16-10-65281-27-18-35-13-21-41,29-23-24,0")
        .expect("should parse");
    assert_eq!(spec.cipher_suites.len(), 15);
    assert_eq!(spec.extensions.len(), 17);
}

#[test]
fn parses_firefox_105_ja3() {
    let spec = parse_ja3("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0")
        .expect("should parse");
    assert_eq!(spec.cipher_suites.len(), 17);
    assert_eq!(spec.extensions.len(), 15);
}
