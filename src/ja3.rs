use std::num::ParseIntError;

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCipherSuite {
    pub kdf_id: String,
    pub aead_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ja3Spec {
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub curves: Vec<u16>,
    pub point_formats: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum Ja3Error {
    #[error("invalid JA3 string")]
    InvalidShape,
    #[error("invalid integer in JA3 string: {0}")]
    InvalidInteger(#[from] ParseIntError),
}

pub fn parse_ja3(ja3: &str) -> Result<Ja3Spec, Ja3Error> {
    let parts: Vec<&str> = ja3.split(',').collect();
    if parts.len() != 5 {
        return Err(Ja3Error::InvalidShape);
    }

    Ok(Ja3Spec {
        cipher_suites: parse_u16_list(parts[1])?,
        extensions: parse_u16_list(parts[2])?,
        curves: parse_u16_list(parts[3])?,
        point_formats: parse_u8_list(parts[4])?,
    })
}

fn parse_u16_list(input: &str) -> Result<Vec<u16>, Ja3Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    input
        .split('-')
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u16>().map_err(Ja3Error::from))
        .collect()
}

fn parse_u8_list(input: &str) -> Result<Vec<u8>, Ja3Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    input
        .split('-')
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u8>().map_err(Ja3Error::from))
        .collect()
}
