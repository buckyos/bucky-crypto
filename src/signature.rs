use generic_array::typenum::{marker_traits::Unsigned, U16, U32, U64, U96};
use generic_array::GenericArray;
use std::ptr::slice_from_raw_parts;
use bucky_time::bucky_time_now;

use crate::*;

impl Default for Signature {
    fn default() -> Self {
        Self {
            sign_time: bucky_time_now(),
            sign: SignData::Rsa1024(GenericArray::default()),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SignData {
    Rsa1024(GenericArray<u32, U32>),
    Rsa2048(GenericArray<u32, U64>),
    Rsa3072(GenericArray<u32, U96>),
    Ecc(GenericArray<u32, U16>),
}

impl SignData {
    pub fn sign_type(&self) -> &str {
        match self {
            Self::Rsa1024(_) => "rsa1024",
            Self::Rsa2048(_) => "rsa2048",
            Self::Rsa3072(_) => "rsa3072",
            Self::Ecc(_) => "ecc",
        }
    }

    pub fn as_slice<'a>(&self) -> &'a [u8] {
        let sign_slice = match self {
            SignData::Rsa1024(sign) => unsafe {
                &*slice_from_raw_parts(
                    sign.as_ptr() as *const u8,
                    std::mem::size_of::<u32>() * U32::to_usize(),
                )
            },
            SignData::Rsa2048(sign) => unsafe {
                &*slice_from_raw_parts(
                    sign.as_ptr() as *const u8,
                    std::mem::size_of::<u32>() * U64::to_usize(),
                )
            },
            SignData::Rsa3072(sign) => unsafe {
                &*slice_from_raw_parts(
                    sign.as_ptr() as *const u8,
                    std::mem::size_of::<u32>() * U96::to_usize(),
                )
            },
            SignData::Ecc(sign) => unsafe {
                &*slice_from_raw_parts(
                    sign.as_ptr() as *const u8,
                    std::mem::size_of::<u32>() * U16::to_usize(),
                )
            },
        };
        sign_slice
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Signature {
    sign_time: u64,
    sign: SignData,
}

impl Signature {
    pub fn new(
        sign_time: u64,
        sign: SignData,
    ) -> Self {
        Self {
            sign_time: sign_time,
            sign: sign,
        }
    }

    pub fn sign(&self) -> &SignData {
        &self.sign
    }

    pub fn as_slice<'a>(&self) -> &'a [u8] {
        self.sign.as_slice()
    }

    pub fn sign_time(&self) -> u64 {
        self.sign_time
    }
}

impl RawEncode for Signature {
    fn raw_measure(&self, _purpose: &Option<RawEncodePurpose>) -> Result<usize, BuckyError> {
        // sign_source_with_ref_index
        let mut size = u64::raw_bytes().unwrap();

        // sign_data: Vec<u8>
        size = size
            + u8::raw_bytes().unwrap()
            + std::mem::size_of::<u32>()
                * match self.sign {
                    SignData::Rsa1024(_) => U32::to_usize(),
                    SignData::Rsa2048(_) => U64::to_usize(),
                    SignData::Rsa3072(_) => U96::to_usize(),
                    SignData::Ecc(_) => U16::to_usize(),
                };

        Ok(size)
    }

    fn raw_encode<'a>(
        &self,
        buf: &'a mut [u8],
        purpose: &Option<RawEncodePurpose>,
    ) -> Result<&'a mut [u8], BuckyError> {
        let bytes = self.raw_measure(purpose).unwrap();
        if buf.len() < bytes {
            let msg = format!(
                "not enough buffer for encode Signature buf, except={}, got={}",
                bytes,
                buf.len()
            );
            error!("{}", msg);

            return Err(BuckyError::new(BuckyErrorCode::OutOfLimit, msg));
        }

        // sign_time
        let buf = self.sign_time.raw_encode(buf, purpose)?;

        // sign_data: Vec<u8>
        let buf = match self.sign {
            SignData::Rsa1024(sign) => {
                let buf = KEY_TYPE_RSA.raw_encode(buf, purpose)?;
                let bytes = std::mem::size_of::<u32>() * U32::to_usize();
                unsafe {
                    std::ptr::copy(
                        sign.as_slice().as_ptr() as *const u8,
                        buf.as_mut_ptr(),
                        bytes,
                    );
                }
                &mut buf[bytes..]
            }
            SignData::Rsa2048(sign) => {
                let buf = KEY_TYPE_RSA2048.raw_encode(buf, purpose)?;
                let bytes = std::mem::size_of::<u32>() * U64::to_usize();
                unsafe {
                    std::ptr::copy(
                        sign.as_slice().as_ptr() as *const u8,
                        buf.as_mut_ptr(),
                        bytes,
                    );
                }
                &mut buf[bytes..]
            }
            SignData::Rsa3072(sign) => {
                let buf = KEY_TYPE_RSA3072.raw_encode(buf, purpose)?;
                let bytes = std::mem::size_of::<u32>() * U96::to_usize();
                unsafe {
                    std::ptr::copy(
                        sign.as_slice().as_ptr() as *const u8,
                        buf.as_mut_ptr(),
                        bytes,
                    );
                }
                &mut buf[bytes..]
            }
            SignData::Ecc(sign) => {
                let buf = KEY_TYPE_SECP256K1.raw_encode(buf, purpose)?;
                let bytes = std::mem::size_of::<u32>() * U16::to_usize();
                unsafe {
                    std::ptr::copy(
                        sign.as_slice().as_ptr() as *const u8,
                        buf.as_mut_ptr(),
                        bytes,
                    );
                }
                &mut buf[bytes..]
            }
        };

        Ok(buf)
    }
}

impl<'de> RawDecode<'de> for Signature {
    fn raw_decode(buf: &'de [u8]) -> Result<(Self, &'de [u8]), BuckyError> {
        let (sign_time, buf) = u64::raw_decode(buf)?;

        let (key_type, buf) = u8::raw_decode(buf)?;

        let (sign, buf) = match key_type {
            KEY_TYPE_RSA => {
                let bytes = std::mem::size_of::<u32>() * U32::to_usize();
                if buf.len() < bytes {
                    return Err(BuckyError::new(
                        BuckyErrorCode::OutOfLimit,
                        "not enough buffer for rsa1024 signature",
                    ));
                }

                let mut sign = GenericArray::default();
                unsafe {
                    std::ptr::copy(
                        buf.as_ptr(),
                        sign.as_mut_slice().as_mut_ptr() as *mut u8,
                        bytes,
                    );
                }

                (SignData::Rsa1024(sign), &buf[bytes..])
            }
            KEY_TYPE_RSA2048 => {
                let bytes = std::mem::size_of::<u32>() * U64::to_usize();
                if buf.len() < bytes {
                    return Err(BuckyError::new(
                        BuckyErrorCode::OutOfLimit,
                        "not enough buffer for rsa2048 signature",
                    ));
                }

                let mut sign = GenericArray::default();
                unsafe {
                    std::ptr::copy(
                        buf.as_ptr(),
                        sign.as_mut_slice().as_mut_ptr() as *mut u8,
                        bytes,
                    );
                }

                (SignData::Rsa2048(sign), &buf[bytes..])
            }
            KEY_TYPE_RSA3072 => {
                let bytes = std::mem::size_of::<u32>() * U96::to_usize();
                if buf.len() < bytes {
                    return Err(BuckyError::new(
                        BuckyErrorCode::OutOfLimit,
                        "not enough buffer for rsa3072 signature",
                    ));
                }

                let mut sign = GenericArray::default();
                unsafe {
                    std::ptr::copy(
                        buf.as_ptr(),
                        sign.as_mut_slice().as_mut_ptr() as *mut u8,
                        bytes,
                    );
                }

                (SignData::Rsa3072(sign), &buf[bytes..])
            }
            KEY_TYPE_SECP256K1 => {
                let bytes = std::mem::size_of::<u32>() * U16::to_usize();
                if buf.len() < bytes {
                    return Err(BuckyError::new(
                        BuckyErrorCode::OutOfLimit,
                        "not enough buffer for secp256k1 signature",
                    ));
                }

                let mut sign = GenericArray::default();
                unsafe {
                    std::ptr::copy(
                        buf.as_ptr(),
                        sign.as_mut_slice().as_mut_ptr() as *mut u8,
                        bytes,
                    );
                }

                (SignData::Ecc(sign), &buf[bytes..])
            }
            _ => {
                return Err(BuckyError::new(
                    BuckyErrorCode::NotMatch,
                    format!("Invalid Signature KeyType:{}", key_type),
                ));
            }
        };

        Ok((
            Self {
                sign_time,
                sign: sign,
            },
            buf,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{RawConvertTo, RawFrom, Signature};

    #[test]
    fn signature() {
        let sig1 = Signature::default();
        let buf = sig1.to_vec().unwrap();
        let sig2 = Signature::clone_from_slice(&buf).unwrap();
        assert_eq!(sig1, sig2)
    }
}
