use crate::*;

use base58::{FromBase58, ToBase58};
use generic_array::typenum::{marker_traits::Unsigned, U32};
use generic_array::GenericArray;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

// Hash
#[derive(Copy, Clone, PartialOrd, PartialEq, Ord, Eq)]
pub struct HashValue(GenericArray<u8, U32>);
pub const HASH_VALUE_LEN: usize = 32;

impl std::fmt::Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HashValue: {}", hex::encode(self.0.as_slice()))
    }
}

impl From<GenericArray<u8, U32>> for HashValue {
    fn from(hash: GenericArray<u8, U32>) -> Self {
        Self(hash)
    }
}

impl From<HashValue> for GenericArray<u8, U32> {
    fn from(hash: HashValue) -> Self {
        hash.0
    }
}

impl AsRef<GenericArray<u8, U32>> for HashValue {
    fn as_ref(&self) -> &GenericArray<u8, U32> {
        &self.0
    }
}

impl Default for HashValue {
    fn default() -> Self {
        Self(GenericArray::default())
    }
}

impl RawFixedBytes for HashValue {
    fn raw_bytes() -> Option<usize> {
        Some(U32::to_usize())
    }
}

impl RawEncode for HashValue {
    fn raw_measure(&self, _purpose: &Option<RawEncodePurpose>) -> BuckyResult<usize> {
        Ok(U32::to_usize())
    }
    fn raw_encode<'a>(
        &self,
        buf: &'a mut [u8],
        _purpose: &Option<RawEncodePurpose>,
    ) -> BuckyResult<&'a mut [u8]> {
        let bytes = Self::raw_bytes().unwrap();
        if buf.len() < bytes {
            let msg = format!(
                "not enough buffer for encode HashValue, except={}, got={}",
                bytes,
                buf.len()
            );
            error!("{}", msg);

            return Err(BuckyError::new(BuckyErrorCode::OutOfLimit, msg));
        }
        unsafe {
            std::ptr::copy(self.0.as_slice().as_ptr(), buf.as_mut_ptr(), bytes);
        }

        Ok(&mut buf[bytes..])
    }
}

impl<'de> RawDecode<'de> for HashValue {
    fn raw_decode(buf: &'de [u8]) -> BuckyResult<(Self, &'de [u8])> {
        let bytes = Self::raw_bytes().unwrap();
        if buf.len() < bytes {
            let msg = format!(
                "not enough buffer for decode HashValue, except={}, got={}",
                bytes,
                buf.len()
            );
            error!("{}", msg);

            return Err(BuckyError::new(BuckyErrorCode::OutOfLimit, msg));
        }
        let mut hash = GenericArray::default();
        unsafe {
            std::ptr::copy(buf.as_ptr(), hash.as_mut_slice().as_mut_ptr(), bytes);
        }
        Ok((Self(hash), &buf[bytes..]))
    }
}

impl From<&[u8; 32]> for HashValue {
    fn from(hash: &[u8; 32]) -> Self {
        Self(GenericArray::clone_from_slice(hash))
    }
}

impl TryFrom<&[u8]> for HashValue {
    type Error = BuckyError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        if v.len() != 32 {
            let msg = format!(
                "HashValue expected bytes of length {} but it was {}",
                32,
                v.len()
            );
            error!("{}", msg);
            return Err(BuckyError::new(BuckyErrorCode::InvalidData, msg));
        }

        let ar: [u8; 32] = v.try_into().unwrap();
        Ok(Self(GenericArray::from(ar)))
    }
}

impl TryFrom<Vec<u8>> for HashValue {
    type Error = BuckyError;
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if v.len() != 32 {
            let msg = format!(
                "HashValue expected bytes of length {} but it was {}",
                32,
                v.len()
            );
            error!("{}", msg);
            return Err(BuckyError::new(BuckyErrorCode::InvalidData, msg));
        }

        let ar: [u8; 32] = v.try_into().unwrap();
        Ok(Self(GenericArray::from(ar)))
    }
}

impl HashValue {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    pub fn len() -> usize {
        HASH_VALUE_LEN
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.0.as_slice())
    }

    pub fn from_hex_string(s: &str) -> BuckyResult<Self> {
        let ret = hex::decode(s).map_err(|e| {
            let msg = format!("invalid hash value hex string: {}, {}", s, e);
            error!("{}", msg);
            BuckyError::new(BuckyErrorCode::InvalidFormat, msg)
        })?;

        Self::clone_from_slice(&ret)
    }

    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    pub fn from_base58(s: &str) -> BuckyResult<Self> {
        let buf = s.from_base58().map_err(|e| {
            let msg = format!("convert base58 str to hashvalue failed, str={}, {:?}", s, e);
            error!("{}", msg);
            BuckyError::new(BuckyErrorCode::InvalidFormat, msg)
        })?;

        if buf.len() != 32 {
            let msg = format!(
                "convert base58 str to hashvalue failed, len unmatch: str={}",
                s
            );
            return Err(BuckyError::new(BuckyErrorCode::InvalidFormat, msg));
        }

        Ok(Self::try_from(buf).unwrap())
    }

    pub fn clone_from_slice(hash: &[u8]) -> BuckyResult<Self> {
        Self::try_from(hash)
    }
}

impl std::fmt::Display for HashValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

impl FromStr for HashValue {
    type Err = BuckyError;
    fn from_str(s: &str) -> BuckyResult<Self> {
        if s.len() == 64 {
            Self::from_hex_string(s)
        } else {
            Self::from_base58(s)
        }
    }
}

impl Hash for HashValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut buff = [0 as u8; 32];
        let _ = self.raw_encode(buff.as_mut(), &None).unwrap();
        state.write(buff.as_ref());
    }
}

impl ProtobufTransform<HashValue> for Vec<u8> {
    fn transform(value: HashValue) -> BuckyResult<Self> {
        Ok(Vec::from(value.0.as_slice()))
    }
}

impl ProtobufTransform<&HashValue> for Vec<u8> {
    fn transform(value: &HashValue) -> BuckyResult<Self> {
        Ok(Vec::from(value.0.as_slice()))
    }
}

impl ProtobufTransform<Vec<u8>> for HashValue {
    fn transform(value: Vec<u8>) -> BuckyResult<Self> {
        if value.len() != HASH_VALUE_LEN {
            return Err(BuckyError::new(
                BuckyErrorCode::InvalidParam,
                format!(
                    "try convert from vec<u8> to named object id failed, invalid len {}",
                    value.len()
                ),
            ));
        }
        let mut id = Self::default();
        unsafe {
            std::ptr::copy(value.as_ptr(), id.as_mut_slice().as_mut_ptr(), value.len());
        }

        Ok(id)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::*;

    #[test]
    fn test() {
        let hash = hash_data("xxxx".as_bytes());
        let hex_id = hash.to_hex_string();
        let base58_id = hash.to_base58();

        println!("{}, {}", hex_id, base58_id);

        let ret = HashValue::from_str(&hex_id).unwrap();
        let ret2 = HashValue::from_str(&base58_id).unwrap();

        assert_eq!(ret, ret2);
    }
}