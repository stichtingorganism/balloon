// Copyright 2019 Stichting Organism
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use subtle::ConstantTimeEq;
use num_bigint::BigUint;
use crate::error::Error;


//
//Constants
//

///512 bits hash is 64 bytes
pub const HASH_LEN: usize = 64;


//
//Helper functions
//

//Borrowed from https://github.com/briansmith/ring
//converts a unsigned 32bit integer to a big endien byte representation
#[inline(always)]
pub fn be_u8_from_u32(value: u32) -> [u8; 4] {
    [
        ((value >> 24) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8
    ]
}

//takes a series of bytes and converts to an unsigned big int.
//le dones it is in little endian
pub fn to_num(b: &[u8], le: bool) -> BigUint {
    if le {
        return BigUint::from_bytes_le(b);
    } else {
        return BigUint::from_bytes_be(b);
    }
}

//https://github.com/brycx/orion/blob/master/src/utilities/util.rs
//Compare two equal length slices in constant time, using the
pub fn compare_ct(a: &[u8], b: &[u8]) -> Option<Error> {
    if a.len() != b.len() {
        return Some(Error::InvalidFormat);
    }

    if a.ct_eq(b).unwrap_u8() == 1 {
        None
    } else {
        return Some(Error::InvalidFormat);
    }
}
