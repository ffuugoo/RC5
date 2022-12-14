use std::{mem, ops};

use num_traits::{
    ops::wrapping::{WrappingAdd, WrappingSub},
    PrimInt,
};

pub struct RC5<T> {
    subkey: Vec<T>,
    rounds: u8,
}

impl<T: Block> RC5<T> {
    pub fn new(key: &[u8], rounds: u8) -> Self {
        assert!(!key.is_empty());
        assert_eq!(key.len() % T::BYTES, 0);

        // Split `key` into `words`
        let mut words = vec![T::default(); key.len() / T::BYTES];

        for byte in (0..key.len()).rev() {
            let word = byte / T::BYTES;

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
                .rotate_left(first.wrapping_add(&second).into());

            subkey[i] = first;
            words[j] = second;

            i = (i + 1) % subkey.len();
            j = (j + 1) % words.len();
        }

        Self { subkey, rounds }
    }

    pub fn encode(&self, plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len(), T::BYTES * 2);

        let (first, second) = plaintext.split_at(T::BYTES);

        let mut first = T::from_le_bytes(first).wrapping_add(&self.subkey[0]);
        let mut second = T::from_le_bytes(second).wrapping_add(&self.subkey[1]);

        for round in 1..=self.rounds as usize {
            first = (first ^ second)
                .rotate_left(second.into())
                .wrapping_add(&self.subkey[round * 2]);

            second = (second ^ first)
                .rotate_left(first.into())
                .wrapping_add(&self.subkey[round * 2 + 1]);
        }

        into_bytes(first, second)
    }

    pub fn decode(&self, ciphertext: &[u8]) -> Vec<u8> {
        assert_eq!(ciphertext.len(), T::BYTES * 2);

        let (first, second) = ciphertext.split_at(T::BYTES);

        let mut first = T::from_le_bytes(first);
        let mut second = T::from_le_bytes(second);

        for round in (1..=self.rounds as usize).rev() {
            second = second
                .wrapping_sub(&self.subkey[round * 2 + 1])
                .rotate_right(first.into()) ^ first;

            first = first
                .wrapping_sub(&self.subkey[round * 2])
                .rotate_right(second.into()) ^ second;
        }

        first = first.wrapping_sub(&self.subkey[0]);
        second = second.wrapping_sub(&self.subkey[1]);

        into_bytes(first, second)
    }
}

fn into_bytes(first: impl Block, second: impl Block) -> Vec<u8> {
    first.to_le_bytes().into_iter().chain(second.to_le_bytes()).collect()
}

pub trait Block:
    Default + PrimInt + WrappingAdd + WrappingSub + ops::BitXor + From<u8> + Into<u32> + Sized
{
    const BYTES: usize = mem::size_of::<Self>();

    const MAGIC_P: Self;
    const MAGIC_Q: Self;

    type ToLeBytesOutput: IntoIterator<Item = u8>;

    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn to_le_bytes(self) -> Self::ToLeBytesOutput;
}

impl Block for u16 {
    const MAGIC_P: Self = 0xB7E1;
    const MAGIC_Q: Self = 0x9E37;

    type ToLeBytesOutput = [u8; 2];

    fn from_le_bytes(bytes: &[u8]) -> Self {
        match bytes {
            &[b1, b2] => Self::from_le_bytes([b1, b2]),
            _ => panic!(),
        }
    }

    fn to_le_bytes(self) -> Self::ToLeBytesOutput {
        self.to_le_bytes()
    }
}

impl Block for u32 {
    const MAGIC_P: Self = 0xB7E15163;
    const MAGIC_Q: Self = 0x9E3779B9;

    type ToLeBytesOutput = [u8; 4];

    fn from_le_bytes(bytes: &[u8]) -> Self {
        match bytes {
            &[b1, b2, b3, b4] => Self::from_le_bytes([b1, b2, b3, b4]),
            _ => panic!(),
        }
    }

    fn to_le_bytes(self) -> Self::ToLeBytesOutput {
        self.to_le_bytes()
    }
}

// RC5 algorithm rotates words "words times".
//
// E.g.:
// - if word is `u16`, it would pass `u16` as parameter to `rotate_*`
// - if word is `u32`, it would pass `u32` as parameter to `rotate_*`
// - etc
//
// However, `rotate_*` methods (for any numeric type) accept `u32` parameter,
// which makes them impossible to use them with `u64` words.
// (Well, *most likely* impossible to use, unless `u64` rotations never overflow `u32`...)
//
// And properly reimplementing them is annoyingly complicated (for such a trivial task),
// so `u64` blocks have to be disabled for now.

/*
impl Block for u64 {
    const MAGIC_P: Self = 0xB7E151628AED2A6B;
    const MAGIC_Q: Self = 0x9E3779B97F4A7C15;

    type ToLeBytesOutput = [u8; 8];

    fn from_le_bytes(bytes: &[u8]) -> Self {
        match bytes {
            &[b1, b2, b3, b4, b5, b6, b7, b8] => Self::from_le_bytes([b1, b2, b3, b4, b5, b6, b7, b8]),
            _ => panic!(),
        }
    }

    fn to_le_bytes(self) -> Self::ToLeBytesOutput {
        self.to_le_bytes()
    }
}
*/

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
}
