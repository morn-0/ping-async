use crate::platform::{PingerConfig, PingerError};
use flume::Sender;
use std::{
    ffi::c_void,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr,
    time::Duration,
};
#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION32 as IP_OPTION_INFORMATION;
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, ERROR_IO_PENDING, HANDLE},
    NetworkManagement::IpHelper::{
        Icmp6CreateFile, Icmp6SendEcho2, IcmpCreateFile, IcmpSendEcho2Ex, ICMPV6_ECHO_REPLY_LH,
        ICMP_ECHO_REPLY,
    },
    System::{
        Threading::{
            CreateEventW, RegisterWaitForSingleObject, UnregisterWait, INFINITE,
            WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
        },
        IO::IO_STATUS_BLOCK,
    },
};

pub struct Pinger<'a> {
    icmp: HANDLE,
    source: Option<IpAddr>,
    target: SocketAddr,
    payload: &'a [u8],
    ttl: u8,
    timeout: Duration,
}

impl<'a> Pinger<'a> {
    pub async fn new(
        config: PingerConfig,
        target: IpAddr,
        payload: &'a [u8],
    ) -> Result<Self, PingerError> {
        let target = SocketAddr::new(target, 0);
        let ttl = config.ttl.unwrap_or(128);
        let timeout = config.timeout.unwrap_or(Duration::from_secs(1));

        let icmp = match target.ip() {
            IpAddr::V4(_) => unsafe { IcmpCreateFile()? },
            IpAddr::V6(_) => unsafe { Icmp6CreateFile()? },
        };
        assert!(!icmp.is_invalid());

        Ok(Pinger {
            icmp,
            source: config.source,
            target,
            payload,
            ttl,
            timeout,
        })
    }

    pub async fn ping(&self) -> Result<Duration, PingerError> {
        unsafe extern "system" fn reply_callback(ptr: *mut c_void, timer_fired: bool) {
            let tx = Box::from_raw(ptr as *mut Sender<bool>);

            if let Err(e) = tx.send(timer_fired) {
                eprintln!("{e}");
            }
        }

        let event = unsafe { CreateEventW(None, true, false, None)? };
        let mut wait_object = HANDLE::default();
        let (tx, rx) = flume::unbounded::<bool>();

        unsafe {
            RegisterWaitForSingleObject(
                &mut wait_object,
                event,
                Some(reply_callback),
                Some(Box::into_raw(Box::new(tx)) as *const _),
                INFINITE,
                WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE,
            )?;
        }

        let size = match self.target.ip() {
            IpAddr::V4(_) => size_of::<ICMP_ECHO_REPLY>(),
            IpAddr::V6(_) => size_of::<ICMPV6_ECHO_REPLY_LH>(),
        } + 8
            + self.payload.len()
            + size_of::<IO_STATUS_BLOCK>();

        let mut reply_buffer: Vec<MaybeUninit<u8>> = Vec::with_capacity(size);
        let mut reply_buffer: Vec<u8> = unsafe {
            let ptr = reply_buffer.as_mut_ptr() as *mut u8;
            ptr.write_bytes(0, size);

            reply_buffer.set_len(size);
            mem::transmute(reply_buffer)
        };

        let ip_option = IP_OPTION_INFORMATION {
            Ttl: self.ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: ptr::null_mut(),
        };

        let error = match self.target.ip() {
            IpAddr::V4(target) => {
                let source = self.source.unwrap_or(Ipv4Addr::UNSPECIFIED.into());

                unsafe {
                    let source = match source {
                        IpAddr::V4(v) => *((&v.octets() as *const u8) as *const u32),
                        IpAddr::V6(_) => return Err(PingerError::Io("todo".to_string())),
                    };
                    let target = *((&target.octets() as *const u8) as *const u32);

                    IcmpSendEcho2Ex(
                        self.icmp,
                        Some(event),
                        None,
                        None,
                        source,
                        target,
                        self.payload.as_ptr() as *const _,
                        self.payload.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        reply_buffer.as_mut_ptr() as *mut _,
                        reply_buffer.len() as u32,
                        self.timeout.as_millis() as u32,
                    )
                }
            }
            IpAddr::V6(target) => {
                let source = self.source.unwrap_or(Ipv6Addr::UNSPECIFIED.into());

                unsafe {
                    let source = match source {
                        IpAddr::V4(_) => return Err(PingerError::Io("todo".to_string())),
                        IpAddr::V6(v) => v,
                    };
                    let source = SocketAddrV6::new(source, 0, 0, 0).into();
                    let target = SocketAddrV6::new(target, 0, 0, 0).into();

                    Icmp6SendEcho2(
                        self.icmp,
                        Some(event),
                        None,
                        None,
                        &source,
                        &target,
                        self.payload.as_ptr() as *const _,
                        self.payload.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        reply_buffer.as_mut_ptr() as *mut _,
                        reply_buffer.len() as u32,
                        self.timeout.as_millis() as u32,
                    )
                }
            }
        };

        if error == 0 {
            let code = unsafe { GetLastError() };

            if code != ERROR_IO_PENDING {
                return Err(PingerError::Io(code.to_hresult().message()));
            }
        }

        if rx.recv_async().await? {
            return Err(PingerError::Timeout(self.timeout));
        }

        if !wait_object.is_invalid() {
            let _ = unsafe { UnregisterWait(wait_object) };
        }

        if !event.is_invalid() {
            let _ = unsafe { CloseHandle(event) };
        }

        let usage = match self.target.ip() {
            IpAddr::V4(_) => {
                unsafe { *(reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY) }.RoundTripTime
            }
            IpAddr::V6(_) => {
                unsafe { *(reply_buffer.as_ptr() as *const ICMPV6_ECHO_REPLY_LH) }.RoundTripTime
            }
        };
        Ok(Duration::from_millis(usage as u64))
    }
}

impl Drop for Pinger<'_> {
    fn drop(&mut self) {
        if !self.icmp.is_invalid() {
            let _ = unsafe { CloseHandle(self.icmp) };
        }
    }
}
