use core::str::FromStr;

use crate::U256;

use super::{EncodableSignature, Parity, SignatureError};

/// A memoized ECDSA signature.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MemoizedSignature {
    sig: k256::ecdsa::Signature,
    parity: Parity,
}

impl MemoizedSignature {
    /// Instantiate from a signature and recovery id
    pub fn from_signature_and_parity<T: TryInto<Parity, Error = E>, E: Into<SignatureError>>(
        sig: k256::ecdsa::Signature,
        parity: T,
    ) -> Result<Self, SignatureError> {
        Ok(Self { sig, parity: parity.try_into().map_err(Into::into)? })
    }

    /// Parses a signature from a byte slice, with a v value
    #[inline]
    pub fn from_bytes_and_parity<T: TryInto<Parity, Error = E>, E: Into<SignatureError>>(
        bytes: &[u8],
        parity: T,
    ) -> Result<Self, SignatureError> {
        let sig = k256::ecdsa::Signature::from_slice(bytes)?;
        Self::from_signature_and_parity(sig, parity)
    }

    /// Creates a [`Signature`] from the serialized `r` and `s` scalar values, which comprise the
    /// ECDSA signature, alongside a `v` value, used to determine the recovery ID.
    ///
    /// See [`k256::ecdsa::Signature::from_scalars`] for more details.
    #[inline]
    pub fn from_scalars_and_parity<T: TryInto<Parity, Error = E>, E: Into<SignatureError>>(
        r: crate::B256,
        s: crate::B256,
        parity: T,
    ) -> Result<Self, SignatureError> {
        let inner = k256::ecdsa::Signature::from_scalars(r.0, s.0)?;
        Self::from_signature_and_parity(inner, parity)
    }

    /// Normalizes the signature into "low S" form as described in
    /// [BIP 0062: Dealing with Malleability][1].
    ///
    /// [1]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    #[inline]
    pub fn normalize_s(&self) -> Option<Self> {
        // Normalize into "low S" form. See:
        // - https://github.com/RustCrypto/elliptic-curves/issues/988
        // - https://github.com/bluealloy/revm/pull/870
        self.sig
            .normalize_s()
            .map(|normalized| Self { sig: normalized, parity: self.parity.inverted() })
    }

    /// Returns the recovery ID.
    #[inline]
    pub const fn recid(&self) -> k256::ecdsa::RecoveryId {
        self.parity.recid()
    }

    #[doc(hidden)]
    #[deprecated(note = "use `Signature::recid` instead")]
    pub const fn recovery_id(&self) -> k256::ecdsa::RecoveryId {
        self.recid()
    }

    /// Recovers an [`Address`] from this signature and the given message by first prefixing and
    /// hashing the message according to [EIP-191](crate::eip191_hash_message).
    ///
    /// [`Address`]: crate::Address
    #[inline]
    pub fn recover_address_from_msg<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<crate::Address, SignatureError> {
        self.recover_from_msg(msg).map(|vk| crate::Address::from_public_key(&vk))
    }

    /// Recovers an [`Address`] from this signature and the given prehashed message.
    ///
    /// [`Address`]: crate::Address
    #[inline]
    pub fn recover_address_from_prehash(
        &self,
        prehash: &crate::B256,
    ) -> Result<crate::Address, SignatureError> {
        self.recover_from_prehash(prehash).map(|vk| crate::Address::from_public_key(&vk))
    }

    /// Recovers a [`VerifyingKey`] from this signature and the given message by first prefixing and
    /// hashing the message according to [EIP-191](crate::eip191_hash_message).
    ///
    /// [`VerifyingKey`]: k256::ecdsa::VerifyingKey
    #[inline]
    pub fn recover_from_msg<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<k256::ecdsa::VerifyingKey, SignatureError> {
        self.recover_from_prehash(&crate::eip191_hash_message(msg))
    }

    /// Recovers a [`VerifyingKey`] from this signature and the given prehashed message.
    ///
    /// [`VerifyingKey`]: k256::ecdsa::VerifyingKey
    #[inline]
    pub fn recover_from_prehash(
        &self,
        prehash: &crate::B256,
    ) -> Result<k256::ecdsa::VerifyingKey, SignatureError> {
        let this = self.normalize_s().unwrap_or(*self);
        k256::ecdsa::VerifyingKey::recover_from_prehash(prehash.as_slice(), &this.sig, this.recid())
            .map_err(Into::into)
    }
}

impl EncodableSignature for MemoizedSignature {
    fn from_rs_and_parity<T: TryInto<Parity, Error = E>, E: Into<SignatureError>>(
        r: U256,
        s: U256,
        parity: T,
    ) -> Result<Self, SignatureError> {
        Self::from_scalars_and_parity(r.into(), s.into(), parity)
    }

    fn r(&self) -> U256 {
        U256::from_be_slice(self.sig.r().to_bytes().as_ref())
    }

    fn s(&self) -> U256 {
        U256::from_be_slice(self.sig.s().to_bytes().as_ref())
    }

    fn v(&self) -> Parity {
        self.parity
    }

    #[inline]
    fn with_parity<T: Into<Parity>>(self, parity: T) -> Self {
        Self { sig: self.sig, parity: parity.into() }
    }
}

impl<'a> TryFrom<&'a [u8]> for MemoizedSignature {
    type Error = SignatureError;

    /// Parses a raw signature which is expected to be 65 bytes long where
    /// the first 32 bytes is the `r` value, the second 32 bytes the `s` value
    /// and the final byte is the `v` value in 'Electrum' notation.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 65 {
            return Err(k256::ecdsa::Error::new().into());
        }
        Self::from_bytes_and_parity(&bytes[..64], bytes[64] as u64)
    }
}

impl FromStr for MemoizedSignature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Self::try_from(&bytes[..])
    }
}

impl From<(k256::ecdsa::Signature, k256::ecdsa::RecoveryId)> for MemoizedSignature {
    fn from(value: (k256::ecdsa::Signature, k256::ecdsa::RecoveryId)) -> Self {
        Self::from_signature_and_parity(value.0, value.1).unwrap()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for MemoizedSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // if the serializer is human readable, serialize as a map, otherwise as a tuple
        if serializer.is_human_readable() {
            use serde::ser::SerializeMap;

            let mut map = serializer.serialize_map(Some(3))?;

            map.serialize_entry("r", &self.r())?;
            map.serialize_entry("s", &self.s())?;

            match self.v() {
                Parity::Eip155(v) => map.serialize_entry("v", &crate::U64::from(v))?,
                Parity::NonEip155(b) => map.serialize_entry("v", &(b as u8 + 27))?,
                Parity::Parity(true) => map.serialize_entry("yParity", "0x1")?,
                Parity::Parity(false) => map.serialize_entry("yParity", "0x0")?,
            }
            map.end()
        } else {
            use serde::ser::SerializeTuple;

            let mut tuple = serializer.serialize_tuple(3)?;
            tuple.serialize_element(&self.r())?;
            tuple.serialize_element(&self.s())?;
            tuple.serialize_element(&self.v().to_u64())?;
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MemoizedSignature {
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
            type Value = MemoizedSignature;

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

                MemoizedSignature::from_rs_and_parity(r, s, v).map_err(serde::de::Error::custom)
            }
        }

        struct TupleVisitor;
        impl<'de> serde::de::Visitor<'de> for TupleVisitor {
            type Value = MemoizedSignature;

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

                MemoizedSignature::from_rs_and_parity(r, s, v).map_err(serde::de::Error::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_map(MapVisitor)
        } else {
            deserializer.deserialize_tuple(3, TupleVisitor)
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use core::str::FromStr;

    use crate::MemoizedSignature;

    #[test]
    fn can_recover_tx_sender_not_normalized() {
        let sig = MemoizedSignature::from_str("48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c8041b").unwrap();
        let hash = b256!("5eb4f5a33c621f32a8622d5f943b6b102994dfe4e5aebbefe69bb1b2aa0fc93e");
        let expected = address!("0f65fe9276bc9a24ae7083ae28e2660ef72df99e");
        assert_eq!(sig.recover_address_from_prehash(&hash).unwrap(), expected);
    }

    #[test]
    fn recover_web3_signature() {
        // test vector taken from:
        // https://web3js.readthedocs.io/en/v1.2.2/web3-eth-accounts.html#sign
        let sig = MemoizedSignature::from_str(
            "b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"
        ).expect("could not parse signature");
        let expected = address!("2c7536E3605D9C16a7a3D7b1898e529396a65c23");
        assert_eq!(sig.recover_address_from_msg("Some data").unwrap(), expected);
    }
}
