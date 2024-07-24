#![allow(unknown_lints, unnameable_types)]

use crate::{
    hex,
    signature::{Parity, SignatureError},
    U256,
};
use alloc::vec::Vec;
use core::str::FromStr;

use super::EncodableSignature;

/// An Ethereum ECDSA signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    v: Parity,
    r: U256,
    s: U256,
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = SignatureError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 65 {
            return Err(SignatureError::FromBytes("expected exactly 65 bytes"));
        }
        Self::from_bytes_and_parity(bytes, bytes[64] as u64)
    }
}

impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Self::try_from(&bytes[..])
    }
}

impl From<&Signature> for [u8; 65] {
    #[inline]
    fn from(value: &Signature) -> [u8; 65] {
        value.as_bytes()
    }
}

impl From<Signature> for [u8; 65] {
    #[inline]
    fn from(value: Signature) -> [u8; 65] {
        value.as_bytes()
    }
}

impl From<&Signature> for Vec<u8> {
    #[inline]
    fn from(value: &Signature) -> Self {
        value.as_bytes().to_vec()
    }
}

impl From<Signature> for Vec<u8> {
    #[inline]
    fn from(value: Signature) -> Self {
        value.as_bytes().to_vec()
    }
}

impl EncodableSignature for Signature {
    fn from_rs_and_parity<T: TryInto<Parity, Error = E>, E: Into<SignatureError>>(
        r: U256,
        s: U256,
        parity: T,
    ) -> Result<Self, SignatureError> {
        Ok(Self { v: parity.try_into().map_err(Into::into)?, r, s })
    }

    #[inline]
    fn r(&self) -> U256 {
        self.r
    }

    #[inline]
    fn s(&self) -> U256 {
        self.s
    }

    #[inline]
    fn v(&self) -> Parity {
        self.v
    }

    #[inline]
    fn with_parity<T: Into<Parity>>(self, parity: T) -> Self {
        Self { v: parity.into(), r: self.r, s: self.s }
    }
}

impl Signature {
    /// Creates a new [`Signature`].
    pub const fn new(v: Parity, r: U256, s: U256) -> Self {
        Self { v, r, s }
    }

    #[doc(hidden)]
    pub fn test_signature() -> Self {
        Self::new(
            false.into(),
            b256!("840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565").into(),
            b256!("25e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1").into(),
        )
    }

    /// Parses a signature from a byte slice, with a v value
    ///
    /// # Panics
    ///
    /// If the slice is not at least 64 bytes long.
    #[inline]
    pub fn from_bytes_and_parity<T: TryInto<Parity, Error = E>, E: Into<SignatureError>>(
        bytes: &[u8],
        parity: T,
    ) -> Result<Self, SignatureError> {
        let r = U256::from_be_slice(&bytes[..32]);
        let s = U256::from_be_slice(&bytes[32..64]);
        Self::from_rs_and_parity(r, s, parity)
    }

    /// Returns the `r` component of this signature.
    #[inline]
    pub const fn r(&self) -> U256 {
        self.r
    }

    /// Returns the `s` component of this signature.
    #[inline]
    pub const fn s(&self) -> U256 {
        self.s
    }

    /// Returns the recovery ID as a `u8`.
    #[inline]
    pub const fn v(&self) -> Parity {
        self.v
    }

    /// Returns the byte-array representation of this signature.
    ///
    /// The first 32 bytes are the `r` value, the second 32 bytes the `s` value
    /// and the final byte is the `v` value in 'Electrum' notation.
    #[inline]
    pub fn as_bytes(&self) -> [u8; 65] {
        let mut sig = [0u8; 65];
        sig[..32].copy_from_slice(&self.r.to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&self.s.to_be_bytes::<32>());
        sig[64] = self.v.y_parity_byte_non_eip155().unwrap_or(self.v.y_parity_byte());
        sig
    }
}

#[cfg(feature = "rlp")]
impl alloy_rlp::Encodable for Signature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header { list: true, payload_length: self.rlp_vrs_len() }.encode(out);
        self.write_rlp_vrs(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.rlp_vrs_len();
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

#[cfg(feature = "rlp")]
impl alloy_rlp::Decodable for Signature {
    fn decode(buf: &mut &[u8]) -> Result<Self, alloy_rlp::Error> {
        let header = alloy_rlp::Header::decode(buf)?;
        let pre_len = buf.len();
        let decoded = Self::decode_rlp_vrs(buf)?;
        let consumed = pre_len - buf.len();
        if consumed != header.payload_length {
            return Err(alloy_rlp::Error::Custom("consumed incorrect number of bytes"));
        }

        Ok(decoded)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // if the serializer is human readable, serialize as a map, otherwise as a tuple
        if serializer.is_human_readable() {
            use serde::ser::SerializeMap;

            let mut map = serializer.serialize_map(Some(3))?;

            map.serialize_entry("r", &self.r)?;
            map.serialize_entry("s", &self.s)?;

            match self.v {
                Parity::Eip155(v) => map.serialize_entry("v", &crate::U64::from(v))?,
                Parity::NonEip155(b) => map.serialize_entry("v", &(b as u8 + 27))?,
                Parity::Parity(true) => map.serialize_entry("yParity", "0x1")?,
                Parity::Parity(false) => map.serialize_entry("yParity", "0x0")?,
            }
            map.end()
        } else {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(3)?;
            tuple.serialize_element(&self.r)?;
            tuple.serialize_element(&self.s)?;
            tuple.serialize_element(&self.v.to_u64())?;
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::MapAccess;

        enum Field {
            R,
            S,
            V,
            YParity,
            Unknown,
        }

        impl<'de> serde::Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(
                        &self,
                        formatter: &mut core::fmt::Formatter<'_>,
                    ) -> core::fmt::Result {
                        formatter.write_str("v, r, s, or yParity")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "r" => Ok(Field::R),
                            "s" => Ok(Field::S),
                            "v" => Ok(Field::V),
                            "yParity" => Ok(Field::YParity),
                            _ => Ok(Field::Unknown),
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct MapVisitor;
        impl<'de> serde::de::Visitor<'de> for MapVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a JSON signature object containing r, s, and v or yParity")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut v: Option<Parity> = None;
                let mut r = None;
                let mut s = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::V => {
                            let value: crate::U64 = map.next_value()?;
                            let parity = value.try_into().map_err(|_| {
                                serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Unsigned(value.as_limbs()[0]),
                                    &"a valid v value matching the range 0 | 1 | 27 | 28 | 35..",
                                )
                            })?;
                            v = Some(parity);
                        }
                        Field::YParity => {
                            let value: crate::Uint<1, 1> = map.next_value()?;
                            if v.is_none() {
                                v = Some(value.into());
                            }
                        }
                        Field::R => {
                            let value: U256 = map.next_value()?;
                            r = Some(value);
                        }
                        Field::S => {
                            let value: U256 = map.next_value()?;
                            s = Some(value);
                        }
                        _ => {}
                    }
                }

                let v = v.ok_or_else(|| serde::de::Error::missing_field("v"))?;
                let r = r.ok_or_else(|| serde::de::Error::missing_field("r"))?;
                let s = s.ok_or_else(|| serde::de::Error::missing_field("s"))?;

                Signature::from_rs_and_parity(r, s, v).map_err(serde::de::Error::custom)
            }
        }

        struct TupleVisitor;
        impl<'de> serde::de::Visitor<'de> for TupleVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a tuple containing r, s, and v")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let r = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let s = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let v: u64 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                Signature::from_rs_and_parity(r, s, v).map_err(serde::de::Error::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_map(MapVisitor)
        } else {
            deserializer.deserialize_tuple(3, TupleVisitor)
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Self::from_rs_and_parity(u.arbitrary()?, u.arbitrary()?, u.arbitrary::<Parity>()?)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for Signature {
    type Parameters = ();
    type Strategy = proptest::strategy::FilterMap<
        <(U256, U256, Parity) as proptest::arbitrary::Arbitrary>::Strategy,
        fn((U256, U256, Parity)) -> Option<Self>,
    >;

    fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;
        proptest::arbitrary::any::<(U256, U256, Parity)>()
            .prop_filter_map("invalid signature", |(r, s, parity)| {
                Self::from_rs_and_parity(r, s, parity).ok()
            })
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[cfg(feature = "rlp")]
    use alloy_rlp::{Decodable, Encodable};

    #[test]
    fn signature_from_str() {
        let s1 = Signature::from_str(
            "0xaa231fbe0ed2b5418e6ba7c19bee2522852955ec50996c02a2fe3e71d30ddaf1645baf4823fea7cb4fcc7150842493847cfb6a6d63ab93e8ee928ee3f61f503500"
        ).expect("could not parse 0x-prefixed signature");

        let s2 = Signature::from_str(
            "aa231fbe0ed2b5418e6ba7c19bee2522852955ec50996c02a2fe3e71d30ddaf1645baf4823fea7cb4fcc7150842493847cfb6a6d63ab93e8ee928ee3f61f503500"
        ).expect("could not parse non-prefixed signature");

        assert_eq!(s1, s2);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_without_parity() {
        let raw_signature_without_y_parity = r#"{
            "r":"0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0",
            "s":"0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05",
            "v":"0x1"
        }"#;

        let signature: Signature = serde_json::from_str(raw_signature_without_y_parity).unwrap();

        let expected = Signature::from_rs_and_parity(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            1,
        )
        .unwrap();

        assert_eq!(signature, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_with_parity() {
        let raw_signature_with_y_parity = serde_json::json!(
            {
            "r":"0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0",
            "s":"0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05",
            "v":"0x1",
            "yParity": "0x1"
        }
        );

        println!("{raw_signature_with_y_parity}");
        let signature: Signature = serde_json::from_value(raw_signature_with_y_parity).unwrap();

        let expected = Signature::from_rs_and_parity(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            1,
        )
        .unwrap();

        assert_eq!(signature, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_both_parity() {
        // this test should be removed if the struct moves to an enum based on tx type
        let signature = Signature::from_rs_and_parity(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            1,
        )
        .unwrap();

        let serialized = serde_json::to_string(&signature).unwrap();
        assert_eq!(
            serialized,
            r#"{"r":"0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0","s":"0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05","yParity":"0x1"}"#
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serialize_v_only() {
        // this test should be removed if the struct moves to an enum based on tx type
        let signature = Signature::from_rs_and_parity(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            1,
        )
        .unwrap();

        let expected = r#"{"r":"0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0","s":"0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05","yParity":"0x1"}"#;

        let serialized = serde_json::to_string(&signature).unwrap();
        assert_eq!(serialized, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_bincode_roundtrip() {
        let signature = Signature::from_rs_and_parity(
            U256::from_str("0xc569c92f176a3be1a6352dd5005bfc751dcb32f57623dd2a23693e64bf4447b0")
                .unwrap(),
            U256::from_str("0x1a891b566d369e79b7a66eecab1e008831e22daa15f91a0a0cf4f9f28f47ee05")
                .unwrap(),
            1,
        )
        .unwrap();

        let bin = bincode::serialize(&signature).unwrap();
        assert_eq!(bincode::deserialize::<Signature>(&bin).unwrap(), signature);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn signature_rlp_decode() {
        // Given a hex-encoded byte sequence
        let bytes = crate::hex!("f84301a048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a010002cef538bc0c8e21c46080634a93e082408b0ad93f4a7207e63ec5463793d");

        // Decode the byte sequence into a Signature instance
        let result = Signature::decode(&mut &bytes[..]).unwrap();

        // Assert that the decoded Signature matches the expected Signature
        assert_eq!(
            result,
            Signature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a3664935310002cef538bc0c8e21c46080634a93e082408b0ad93f4a7207e63ec5463793d01").unwrap()
        );
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn signature_rlp_encode() {
        // Given a Signature instance
        let sig = Signature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c8041b").unwrap();

        // Initialize an empty buffer
        let mut buf = vec![];

        // Encode the Signature into the buffer
        sig.encode(&mut buf);

        // Define the expected hex-encoded string
        let expected = "f8431ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804";

        // Assert that the encoded buffer matches the expected hex-encoded string
        assert_eq!(hex::encode(&buf), expected);
    }

    #[cfg(feature = "rlp")]
    #[test]
    fn signature_rlp_length() {
        // Given a Signature instance
        let sig = Signature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c8041b").unwrap();

        // Assert that the length of the Signature matches the expected length
        assert_eq!(sig.length(), 69);
    }
}
