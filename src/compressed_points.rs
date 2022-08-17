use core::fmt::Debug;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use dalek_ff_group::field::FieldElement;
use dalek_ff_group::field::SQRT_M1;
use dalek_ff_group::field::EDWARDS_D;
use ff::Field;
use ff::PrimeField;
//use curve25519_dalek::field::FieldElement;
use curve25519_dalek::traits::Identity;
use hex::FromHexError;
use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use hex::FromHex;

#[derive(Debug)]
pub struct CompressedLegacyX(pub [u8; 32]);

impl FromHex for CompressedLegacyX {
    type Error = FromHexError;
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::from_hex(hex)?;
        Ok(CompressedLegacyX(bytes))
    }
}

impl CompressedLegacyX {
    /// Copy this `CompressedEdwardsX` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn to_compressed_edwards_x(&self) -> CompressedEdwardsX {
        /* Factor to multiply the X coordinate with to convert from the legacy to the Ed25519 curve */
        const LEGACY_TO_ED25519: [u8; 32] = [
            0xe7, 0x81, 0xba, 0x00, 0x55, 0xfb, 0x91, 0x33, 0x7d, 0xe5, 0x82, 0xb4, 0x2e, 0x2c,
            0x5e, 0x3a, 0x81, 0xb0, 0x03, 0xfc, 0x23, 0xf7, 0x84, 0x2d, 0x44, 0xf9, 0x5f, 0x9f,
            0x0b, 0x12, 0xd9, 0x70,
        ];
        let legacy_to_ed25519_factor = FieldElement::from_repr(LEGACY_TO_ED25519).unwrap();
        //println!("{:?}", c_y.to_bytes());
        let mut bytes = self.to_bytes();
        let compressed_sign_bit = Choice::from(bytes[31] >> 7);
        bytes[31] &= !(1 << 7);
        let uc_x = FieldElement::from_repr(bytes).unwrap();
        let res = legacy_to_ed25519_factor * uc_x;
        let mut bytes = res.to_repr();
        bytes[31] ^= compressed_sign_bit.unwrap_u8() << 7;
        CompressedEdwardsX(bytes)
    }
}

/// In "Edwards x"/ "libuecc" format, the curve point \\((x,y)\\) is
/// determined by the \\(x\\)-coordinate and the sign of \\(y\\).
///
/// The first 255 bits of a `CompressedEdwardsX` represent the
/// \\(x\\)-coordinate.  The high bit of the 32nd byte gives the sign of \\(y\\).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct CompressedEdwardsX(pub [u8; 32]);

impl ConstantTimeEq for CompressedEdwardsX {
    fn ct_eq(&self, other: &CompressedEdwardsX) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl Debug for CompressedEdwardsX {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "CompressedEdwardsX: {:?}", self.as_bytes())
    }
}

impl CompressedEdwardsX {
    /// View this `CompressedEdwardsX` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy this `CompressedEdwardsX` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Attempt to decompress to an `EdwardsPoint`.
    ///
    /// Returns `None` if the input is not the \\(x\\)-coordinate of a
    /// curve point.
    pub fn decompress(&self) -> Option<EdwardsPoint> {
        // The variables uc_* refer to the X, Y, Z and X²~XX members of the uncompressed EP.
        let mut bytes = self.to_bytes();
        let compressed_sign_bit = Choice::from(&bytes[31] >> 7);
        bytes[31] &= !(1 << 7);

        let uc_x = FieldElement::from_repr(bytes).unwrap();
        let uc_z = FieldElement::one();
        let uc_xx = uc_x.square();
        let s = -uc_xx - uc_z;
        let t = uc_xx * EDWARDS_D - uc_z;
        let (is_valid_x_coord, mut uc_y) = FieldElement::sqrt_ratio_i(&s, &t);

        if is_valid_x_coord.unwrap_u8() != 1u8 {
            return None;
        }
        // FieldElement::sqrt_ratio_i always returns the nonnegative square root,
        // so we negate according to the supplied sign bit.
        uc_y.conditional_negate(compressed_sign_bit);

        // curve25519_dalek::edwards does not expose FieldElements as members
        // and guarantees each instance of EdwardsPoint to be a valid Point
        // on the Edwards-Curve, so building it from arbitrary values is not supported.
        // So instead of returning `Some(EdwardsPoint{ X, Y, Z, T: &X * &Y })`
        // the following (inperformant) hack using their compressed Y Implementation
        // is used.
        let mut bytes = uc_y.to_repr();
        bytes[31] ^= uc_x.is_negative().unwrap_u8() << 7;
        CompressedEdwardsY(bytes).decompress()
    }
}

#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "serde")]
impl Serialize for CompressedEdwardsX {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(32)?;
        for byte in self.as_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for CompressedEdwardsX {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompressedEdwardsXVisitor;

        impl<'de> Visitor<'de> for CompressedEdwardsXVisitor {
            type Value = CompressedEdwardsX;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("32 bytes of data")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<CompressedEdwardsX, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                for i in 0..32 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }
                Ok(CompressedEdwardsX(bytes))
            }
        }

        deserializer.deserialize_tuple(32, CompressedEdwardsXVisitor)
    }
}

impl Identity for CompressedEdwardsX {
    fn identity() -> CompressedEdwardsX {
        CompressedEdwardsX([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
    }
}

impl Default for CompressedEdwardsX {
    fn default() -> CompressedEdwardsX {
        CompressedEdwardsX::identity()
    }
}

impl CompressedEdwardsX {
    /// Construct a `CompressedEdwardsX` from a slice of bytes.
    ///
    /// # Panics
    ///
    /// If the input `bytes` slice does not have a length of 32.
    pub fn from_slice(bytes: &[u8]) -> CompressedEdwardsX {
        let mut tmp = [0u8; 32];

        tmp.copy_from_slice(bytes);

        CompressedEdwardsX(tmp)
    }
}

impl Zeroize for CompressedEdwardsX {
    /// Reset this `CompressedEdwardsX` to the compressed form of the identity element.
    fn zeroize(&mut self) {
        self.0.zeroize();
        self.0[0] = 1;
    }
}

pub trait FieldElementExt {
    fn conditional_negate(&mut self, negate: Choice);
    fn is_negative(&self) -> Choice; //TODO use upstreamed `is_odd`-variant once next release is out
    fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement); //TODO use upstreamed variant once next release is out
}

impl FieldElementExt for FieldElement {
    fn conditional_negate(&mut self, negate: Choice) {
        self.conditional_assign(&(-(*self)), negate);
    }

    fn is_negative(&self) -> Choice {
        // ed25519 paper: `x` is negative if the low bit is set.
        let bytes = self.to_repr();
        (bytes[0] & 1).into()
    }

    fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        let v3 = v.square() * v;
        let v7 = v3.square() * v;
        let mut r = (*u * v3)
            * (*u * v7).pow((-FieldElement::from(5u8)) * FieldElement::from(8u8).invert().unwrap());
        let check = (*v) * r.square();
        let i = SQRT_M1;

        let correct_sign = check.ct_eq(u);
        let flipped_sign = check.ct_eq(&(-(*u)));
        let flipped_sign_i = check.ct_eq(&((-(*u)) * i));

        let r_prime = i * r;

        r.conditional_assign(&r_prime, flipped_sign | flipped_sign_i);

        let r_is_negative = r.is_negative();
        r.conditional_assign(&(-r), r_is_negative.into());

        let was_non_zero_square = correct_sign | flipped_sign;

        (was_non_zero_square, r)
    }
}

pub trait EdwardsPointExt {
    fn compress_x(&self) -> CompressedEdwardsX;
}

impl EdwardsPointExt for EdwardsPoint {
    fn compress_x(&self) -> CompressedEdwardsX {
        /* this would return the following implementation if the fields
        * of EdwardsPoint were not crate-private:
        * let recip = self.Z.invert();
        * let x = &self.X * &recip;
        * let y = &self.Y * &recip;
        * let mut s: [u8; 32];

        * s = x.to_bytes();
        * s[31] ^= y.is_negative().unwrap_u8() << 7;
        * CompressedEdwardsX(s)
        * As done for the decompression impl, work around these fields using compressed-y repr:
        * Accepting decreased performance in favor of not forking the library. */
        // The variables uc_* refer to the X, Y, Z and X²~XX members of the uncompressed EP.
        let c_y = self.compress();
        //println!("{:?}", c_y.to_bytes());
        let mut bytes = c_y.to_bytes();
        let compressed_sign_bit = Choice::from(bytes[31] >> 7);
        bytes[31] &= !(1 << 7);
        let uc_y = FieldElement::from_repr(bytes).unwrap();
        let uc_z = FieldElement::one();
        let uc_yy = uc_y.square();
        let u = uc_yy - uc_z; // u =  y²-1
        let v = uc_yy * EDWARDS_D + uc_z; // v = dy²+1
        let (_, mut uc_x) = FieldElement::sqrt_ratio_i(&u, &v);
        // as this is part of upstreams decompression and self is guaranteed to be a valid Point,
        // this cannot be an invalid y-coord.

        // FieldElement::sqrt_ratio_i always returns the nonnegative square root,
        // so we negate according to the supplied sign bit.
        uc_x.conditional_negate(compressed_sign_bit);

        let recip = uc_z.invert().unwrap();
        let x = uc_x * recip;
        let y = uc_y * recip;
        let mut s: [u8; 32];

        s = x.to_repr();
        s[31] ^= y.is_negative().unwrap_u8() << 7;
        CompressedEdwardsX(s)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use dalek_ff_group::field::FieldElement;
    use dalek_ff_group::field::SQRT_M1;
    use hex::FromHex;
    //use curve25519_dalek::constants::SQRT_M1 as dalek_SQRT_M1;
    //use curve25519_dalek::constants::EDWARDS_D as dalek_EDWARDS_D;
    use crate::compressed_points::FieldElementExt;
    use ff::Field;
    use ff::PrimeField;

    /* both tests work if dalek had the constants public
    #[test]
    fn test_sqrtm1_equality() {
        let m1 = SQRT_M1;
        let dalek_m1 = dalek_SQRT_M1;
        assert_eq!(m1.to_repr(), dalek_m1.to_bytes());
    }

    #[test]
    fn test_edwards_d_equality() {
        let d = FieldElement::get_edwards_d();
        let dalek_d = dalek_EDWARDS_D;
        assert_eq!(d.to_repr(), dalek_d.to_bytes());

    }
    */

    #[test]
    fn no_error_on_unwrap() {
        let expected_compressed_y =
            "1EE08564F758E3B2FDA686428D29D008E31D3D9B3F8E4CE51A80C0544A15FFA4";
        let cy = CompressedEdwardsY(
            <[u8; 32]>::from_hex(expected_compressed_y).expect("Decoding failed"),
        );
        cy.decompress();
        let mut bytes = cy.to_bytes();
        bytes[31] &= !(1 << 7);
        FieldElement::from_repr(bytes).unwrap();
    }

    #[test]
    fn sqrt_ratio_behavior() {
        let zero = FieldElement::zero();
        let one = FieldElement::one();
        let i = SQRT_M1;
        let two = one + one; // 2 is nonsquare mod p.
        let four = two + two; // 4 is square mod p.

        // 0/0 should return (1, 0) since u is 0
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&zero, &zero);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt, zero);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 1/0 should return (0, 0) since v is 0, u is nonzero
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&one, &zero);
        assert_eq!(choice.unwrap_u8(), 0);
        assert_eq!(sqrt, zero);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 2/1 is nonsquare, so we expect (0, sqrt(i*2))
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&two, &one);
        assert_eq!(choice.unwrap_u8(), 0);
        assert_eq!(sqrt.square(), two * i);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 4/1 is square, so we expect (1, sqrt(4))
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&four, &one);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt.square(), four);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);

        // 1/4 is square, so we expect (1, 1/sqrt(4))
        let (choice, sqrt) = FieldElement::sqrt_ratio_i(&one, &four);
        assert_eq!(choice.unwrap_u8(), 1);
        assert_eq!(sqrt.square() * four, one);
        assert_eq!(sqrt.is_negative().unwrap_u8(), 0);
    }
}
