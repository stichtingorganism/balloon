// Copyright 2021 Stichting Organism
// Copyright 2018 The SiO4 Project Developers
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

// #![forbid(unsafe_code)]
// #![no_std]

//
//Balloon Hashing
//

// extern crate alloc;

#[derive(Debug, Copy, Clone, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("salt must be at least 4 bytes long")]
    InvalidSalt,
    #[error("space must be greater than the digest length")]
    InvalidSpace,
    #[error("time must be greater than or equal to 1")]
    InvalidTime,
    #[error("invalid format is passed to Balloon")]
    InvalidFormat,
}

pub use blake3::Hash;

use subtle::ConstantTimeEq;

// use alloc::{vec, vec::Vec};
use core::convert::TryInto;
use digest::{generic_array::GenericArray, Digest};

//
//Balloon
//

/// Internal state of a Balloon instance
pub struct Balloon<D>
where
    D: Digest,
{
    /// Data buffer
    buffer: Vec<GenericArray<u8, D::OutputSize>>,
    /// Hasher Instance
    digest: D,
    /// Space is the number of digest-sized blocks in buffer (space cost).
    space: usize,
    /// Time is the number of rounds (time cost).
    time: usize,
    /// Delta is Number of dependencies per block.
    delta: usize,
}

impl<D> Balloon<D>
where
    D: Digest,
{
    pub fn new(space: usize, time: usize, delta: usize) -> Self {
        Balloon {
            buffer: vec![Default::default(); space],
            digest: D::new(),
            space,
            time,
            delta,
        }
    }

    pub fn reconfigure(&mut self, space: usize, time: usize, delta: usize) {
        self.space = space;
        self.time = time;
        self.delta = delta;
    }

    pub fn process(&mut self, pass: &[u8], salt: &[u8]) -> GenericArray<u8, D::OutputSize> {
        let Balloon {
            buffer,
            digest,
            space,
            time,
            delta,
        } = self;

        let (space, time, delta) = (*space, *time, *delta);
        assert!(space > 0);

        // reset buffer for the current size (may reallocate)
        buffer.resize_with(space, Default::default);

        let mut counter: u64 = 0;

        //
        // Step 1. Expansion
        //

        // First block combines counter (0) + password + salt
        digest.update(&counter.to_le_bytes());

        // Increment counter
        counter += 1;

        digest.update(salt);
        digest.update(pass);
        // Get the hash and add to buffer as the first block.
        // We also reset the digest state.
        buffer[0] = digest.finalize_reset();

        // Expand loop based on block size that fits space
        for i in 1..space {
            // Add this count
            digest.update(&counter.to_le_bytes());
            // Increment counter
            counter += 1;
            // Add previous hash
            digest.update(&buffer[i - 1]);
            // Change last block to this new one
            // We also reset the digest state.
            buffer[i] = digest.finalize_reset();
        }

        //
        // Step 2. Mix buffer contents.
        //

        // Outest loop is time controlled
        for t in 0..time {
            // Inner loop is space bound
            for m in 0..space {
                //
                //Step 2a. Hash last and current blocks.
                //

                // Add this count
                digest.update(&counter.to_le_bytes());
                // Increment counter
                counter += 1;

                digest.update(&buffer[(space - 1 + m) % space]);

                // Add to buffer
                buffer[m] = digest.finalize_reset();

                //
                //Step 2b. Hash in pseudorandomly chosen blocks.
                //

                // This is bound by delta parameter
                for i in 0..delta {
                    // Add this count
                    digest.update(&counter.to_le_bytes());
                    // Increment counter
                    counter += 1;
                    // Mix salt
                    digest.update(salt);
                    // Mix time index
                    digest.update(&(t as u64).to_le_bytes());
                    // Mix space index
                    digest.update(&(m as u64).to_le_bytes());
                    // Mix delta index
                    digest.update(&(i as u64).to_le_bytes());

                    // Get challange index
                    let x = u64::from_le_bytes(
                        digest.finalize_reset()[..8]
                            .try_into()
                            .expect("digest contains less than 8 bytes?"),
                    ) as usize;

                    // Add this count
                    digest.update(&counter.to_le_bytes());
                    // Increment counter
                    counter += 1;

                    digest.update(&buffer[m]);
                    digest.update(&buffer[x % space]);
                    //add to buffer
                    buffer[m] = digest.finalize_reset();
                } // end of delta loop
            } // end of space loop
        } // end of time loop

        //
        // Step 3. Extract output from buffer.
        //

        // return the last block
        buffer[space - 1].clone()
    }
}

//new ballon instance with given space and time parameters
pub fn balloon(
    passy: &[u8],
    salty: &[u8],
    space: usize,
    time: usize,
    delta: usize,
) -> Result<Hash, Error> {
    //
    // Base Checks
    //

    //space must be greater than the digest length
    if space < 1 {
        return Err(Error::InvalidSpace);
    }
    //time must be greater than or equal to
    if time < 1 {
        return Err(Error::InvalidTime);
    }
    //salt must be at least 4 bytes long
    if salty.len() < 4 {
        return Err(Error::InvalidSalt);
    }

    let mut ctx = Balloon::<blake3::Hasher>::new(space, time, delta);

    let res = ctx.process(passy, salty);

    //hash output
    Ok(blake3::hash(&res))
}

//Verify BALLOON-BLAKE3 derived key in constant time.
pub fn verify(
    val: &Hash,
    passy: &[u8],
    salty: &[u8],
    space: usize,
    time: usize,
    delta: usize,
) -> Result<bool, Error> {
    match balloon(passy, salty, space, time, delta) {
        //no errors continue
        Ok(res) => {
            //do we have a match
            match compare_ct(res.as_bytes(), val.as_bytes()) {
                Some(_) => Ok(false),
                //no res means match
                None => Ok(true),
            }
        }

        Err(e) => Err(e),
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works2() {
        let password = [0u8, 1u8, 2u8, 3u8, 0u8, 1u8, 2u8, 3u8];
        let salt = [0u8, 1u8, 2u8, 3u8, 3u8];
        let test = balloon(&password, &salt, 24, 18, 5).unwrap();
        assert!(verify(&test, &password, &salt, 24, 18, 5).unwrap());
    }
}
