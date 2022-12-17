use std::{fmt, mem, ops::BitXor};

use num_traits::{
    ops::wrapping::{WrappingAdd, WrappingSub},
    PrimInt,
};

pub struct RC5<T> {
    subkey: Vec<T>,
    rounds: u8,
}

impl<'a, T: Block<'a>> RC5<T>
where
    TryFromU8SliceError<'a, T::Bytes>: fmt::Debug,
{
    pub fn new(key: &[u8], rounds: u8) -> Self {
        assert!(!key.is_empty(), "key is empty");
        assert_eq!(key.len() % T::bytes(), 0, "key length have to be a multiple of word length");

        // Split `key` into `words`
        let mut words = vec![T::default(); key.len() / T::bytes()];

        for byte in (0..key.len()).rev() {
            let word = byte / T::bytes();

            words[word] = words[word]
                .rotate_left(8)
                .wrapping_add(&key[byte].into());
        }

        // Initialize `subkey` with *magic* values
        let subkey_len = 2 * (rounds as usize + 1);

        let mut subkey = Vec::with_capacity(subkey_len);

        let mut word = T::MAGIC_P;
        subkey.push(word);

        for _ in 1..subkey_len {
            word = word.wrapping_add(&T::MAGIC_Q);
            subkey.push(word);
        }

        // Derive `subkey` from `words`
        let (mut i, mut j, mut first, mut second) = (0, 0, T::default(), T::default());

        for _ in 0..(3 * words.len().max(subkey.len())) {
            first = subkey[i]
                .wrapping_add(&first)
                .wrapping_add(&second)
                .rotate_left(3);

            second = words[j]
                .wrapping_add(&first)
                .wrapping_add(&second)
                .uniform_rotate_left(first.wrapping_add(&second).into());

            subkey[i] = first;
            words[j] = second;

            i = (i + 1) % subkey.len();
            j = (j + 1) % words.len();
        }

        Self { subkey, rounds }
    }

    pub fn encode(&self, plaintext: &'a [u8]) -> Vec<u8> {
        assert_eq!(
            plaintext.len(),
            T::bytes() * 2,
            "plaintext length have to be exactly two words",
        );

        let (first, second) = plaintext.split_at(T::bytes());

        let mut first = T::from_le_bytes_slice(first).wrapping_add(&self.subkey[0]);
        let mut second = T::from_le_bytes_slice(second).wrapping_add(&self.subkey[1]);

        for round in 1..=self.rounds as usize {
            first = (first ^ second)
                .uniform_rotate_left(second.into())
                .wrapping_add(&self.subkey[round * 2]);

            second = (second ^ first)
                .uniform_rotate_left(first.into())
                .wrapping_add(&self.subkey[round * 2 + 1]);
        }

        first.to_le_bytes_vec(second)
    }

    pub fn decode(&self, ciphertext: &'a [u8]) -> Vec<u8> {
        assert_eq!(
            ciphertext.len(),
            T::bytes() * 2,
            "ciphertext length have to be exactly two words",
        );

        let (first, second) = ciphertext.split_at(T::bytes());

        let mut first = T::from_le_bytes_slice(first);
        let mut second = T::from_le_bytes_slice(second);

        for round in (1..=self.rounds as usize).rev() {
            second = second
                .wrapping_sub(&self.subkey[round * 2 + 1])
                .uniform_rotate_right(first.into()) ^ first;

            first = first
                .wrapping_sub(&self.subkey[round * 2])
                .uniform_rotate_right(second.into()) ^ second;
        }

        first = first.wrapping_sub(&self.subkey[0]);
        second = second.wrapping_sub(&self.subkey[1]);

        first.to_le_bytes_vec(second)
    }
}

pub trait Block<'a>:
    Default
    + PrimInt
    + WrappingAdd
    + WrappingSub
    + UniformRotate
    + BitXor
    + From<u8>
    + Sized
{
    const MAGIC_P: Self;
    const MAGIC_Q: Self;

    type Bytes: TryFrom<&'a [u8]> + AsRef<[u8]>;

    fn from_le_bytes(bytes: Self::Bytes) -> Self;
    fn to_le_bytes(self) -> Self::Bytes;

    fn bytes() -> usize {
        mem::size_of::<Self>()
    }

    fn from_le_bytes_slice(bytes: &'a [u8]) -> Self
    where
        TryFromU8SliceError<'a, Self::Bytes>: fmt::Debug,
    {
        Self::from_le_bytes(bytes.try_into().unwrap())
    }

    fn to_le_bytes_vec(self, other: Self) -> Vec<u8> {
        let mut bytes = Vec::from(self.to_le_bytes().as_ref());
        bytes.extend_from_slice(other.to_le_bytes().as_ref());
        bytes
    }
}

pub type TryFromU8SliceError<'a, T> = <T as TryFrom<&'a [u8]>>::Error;

macro_rules! block {
    ($type:ty, $magic_p:literal, $magic_q:literal $(,)?) => {
        impl<'a> Block<'a> for $type {
            const MAGIC_P: Self = $magic_p;
            const MAGIC_Q: Self = $magic_q;

            type Bytes = [u8; mem::size_of::<Self>()];

            fn from_le_bytes(bytes: Self::Bytes) -> Self {
                Self::from_le_bytes(bytes)
            }

            fn to_le_bytes(self) -> Self::Bytes {
                self.to_le_bytes()
            }
        }
    };
}

block!(u8, 0xB7, 0x9F);
block!(u16, 0xB7E1, 0x9E37);
block!(u32, 0xB7E15163, 0x9E3779B9);
block!(u64, 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15);
block!(u128, 0xB7E151628AED2A6ABF7158809CF4F3C7, 0x9E3779B97F4A7C15F39CC0605CEDC835);

// RC5 algorithm rotates words "words times".
//
// E.g.:
// - if word is `u16`, it would pass `u16` as parameter to `rotate_*`
// - if word is `u32`, it would pass `u32` as parameter to `rotate_*`
// - etc
//
// However, `rotate_*` methods (for any numeric type) accept `u32` parameter,
// which makes them impossible to use with `u64` words (unless all `u64` rotations
// are always guaranteed to fit `u32` value... which I won't even try to prove).
//
// So, to be able to implement RC5 for `u64` words, `rotate_*` (and `checked_shift_*`) methods
// are re-implemented to accept `Self` parameters.
//
// Implementing these methods "generically" (e.g., as a trait depending on a bunch of super-traits
// with default implementations for all methods) is also a major pain, so implementations are
// generated with a macro.

pub trait UniformRotate {
    fn uniform_rotate_left(self, other: Self) -> Self;
    fn uniform_rotate_right(self, other: Self) -> Self;
}

pub trait NothrowShift {
    fn nothrow_shift_left(self, other: Self) -> Self;
    fn nothrow_shift_right(self, other: Self) -> Self;
}

macro_rules! rotate {
    (@rotate $method:ident, $first:ident, $second:ident $(,)?) => {
        fn $method(self, other: Self) -> Self {
            let bits = mem::size_of::<Self>() * 8;
            let shift_by = other & (bits - 1) as Self;
            self.$first(shift_by) | self.$second(bits as Self - shift_by)
        }
    };

    (@shift $method:ident, $op:path $(,)?) => {
        fn $method(self, other: Self) -> Self {
            if (other as usize) < mem::size_of::<Self>() * 8 {
                $op(self, other)
            } else {
                0
            }
        }
    };

    ($type:ty) => {
        impl UniformRotate for $type {
            rotate!(@rotate uniform_rotate_left, nothrow_shift_left, nothrow_shift_right);
            rotate!(@rotate uniform_rotate_right, nothrow_shift_right, nothrow_shift_left);
        }

        impl NothrowShift for $type {
            rotate!(@shift nothrow_shift_left, std::ops::Shl::shl);
            rotate!(@shift nothrow_shift_right, std::ops::Shr::shr);
        }
    };
}

rotate!(u8);
rotate!(u16);
rotate!(u32);
rotate!(u64);
rotate!(u128);

#[cfg(test)]
mod tests {
    use super::*;

    // This function should return a cipher text for a given key and plaintext
    fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
        RC5::<u32>::new(&key, 12).encode(&plaintext)
    }

    // This function should return a plaintext for a given key and ciphertext
    fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        RC5::<u32>::new(&key, 12).decode(&ciphertext)
    }

    #[test]
    fn encode_a() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = encode(key, pt);
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
        let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = encode(key, pt);
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = decode(key, ct);
        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
        let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = decode(key, ct);
        assert!(&pt[..] == &res[..]);
    }

    macro_rules! test_rc5 {
        (
            $encode:ident,
            $decode:ident,
            $block:ty,
            $rounds:expr,
            $key:expr,
            $pt:expr,
            $ct:expr
            $(,)?
        ) => {
            #[test]
            fn $encode() {
                const KEY: &[u8] = &$key;
                const PT: &[u8] = &$pt;
                const CT: &[u8] = &$ct;
                let res = RC5::<$block>::new(KEY, $rounds).encode(PT);
                assert_eq!(&CT[..], &res[..]);
            }

            #[test]
            fn $decode() {
                const KEY: &[u8] = &$key;
                const PT: &[u8] = &$pt;
                const CT: &[u8] = &$ct;
                let res = RC5::<$block>::new(KEY, $rounds).decode(CT);
                assert_eq!(&PT[..], &res[..]);
            }
        };
    }

    test_rc5!(
        encode_rc5_8_12_4,
        decode_rc5_8_12_4,
        u8,
        12,
        [0x00, 0x01, 0x02, 0x03],
        [0x00, 0x01],
        [0x21, 0x2A],
    );

    test_rc5!(
        encode_rc5_16_16_8,
        decode_rc5_16_16_8,
        u16,
        16,
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        [0x00, 0x01, 0x02, 0x03],
        [0x23, 0xA8, 0xD7, 0x2E],
    );

    test_rc5!(
        encode_rc5_32_20_16,
        decode_rc5_32_20_16,
        u32,
        20,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ],
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        [0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73],
    );

    test_rc5!(
        encode_rc5_64_24_24,
        decode_rc5_64_24_24,
        u64,
        24,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ],
        [
            0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02,
            0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71, 0x78, 0xDA,
        ],
    );

    test_rc5!(
        encode_rc5_128_28_32,
        decode_rc5_128_28_32,
        u128,
        28,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

        ],
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ],
        [
            0xEC, 0xA5, 0x91, 0x09, 0x21, 0xA4, 0xF4, 0xCF,
            0xDD, 0x7A, 0xD7, 0xAD, 0x20, 0xA1, 0xFC, 0xBA,
            0x06, 0x8E, 0xC7, 0xA7, 0xCD, 0x75, 0x2D, 0x68,
            0xFE, 0x91, 0x4B, 0x7F, 0xE1, 0x80, 0xB4, 0x40,
        ],
    );
}
