use std::{net::IpAddr, time::Duration};
use thiserror::Error;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::Pinger;

#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use windows::Pinger;

#[derive(Default)]
pub struct PingerConfig {
    pub source: Option<IpAddr>,
    pub ttl: Option<u8>,
    pub timeout: Option<Duration>,
    #[cfg(target_family = "unix")]
    pub identifier: Option<u16>,
    #[cfg(target_family = "unix")]
    pub sequence: Option<u16>,
}

#[derive(Error, Debug)]
pub enum PingerError {
    #[error("Timeout, {0:?}")]
    Timeout(Duration),
    #[cfg(target_family = "unix")]
    #[error("Io, {0:?}")]
    Io(#[from] std::io::Error),
    #[cfg(target_family = "windows")]
    #[error("Io, {0:?}")]
    Io(String),
}

#[cfg(target_family = "windows")]
impl From<::windows::core::Error> for PingerError {
    fn from(value: ::windows::core::Error) -> Self {
        PingerError::Io(value.message())
    }
}

#[cfg(target_family = "windows")]
impl From<flume::RecvError> for PingerError {
    fn from(value: flume::RecvError) -> Self {
        PingerError::Io(value.to_string())
    }
}
