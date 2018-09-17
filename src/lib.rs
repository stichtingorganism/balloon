// Copyright 2018 Stichting Organism
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

//
//External Crates
//
extern crate blake2_rfc;
extern crate subtle;
extern crate num_bigint;
extern crate num_traits;

//
//Balloon Hashing
//

/*
 - https://eprint.iacr.org/2016/027.pdf
 - https://crypto.stanford.edu/balloon/
 - https://github.com/codahale/balloonhash/blob/master/src/main/java/com/codahale/balloonhash/BalloonHash.java
 - https://github.com/moxnetwork/mox/blob/master/attic/balloon.go
 - https://github.com/nachonavarro/balloon-hashing

    The algorithm consists of three main parts, as explained in the paper. 
    The first step is the expansion, in which the system fills up a buffer 
    with pseudorandom bytes derived from the password and salt by computing 
    repeatedly the hash function on a combination of the password and the previous hash. 
    The second step is mixing, in which the system mixes time_cost number of times the 
    pseudorandom bytes in the buffer. At each step in the for loop, it updates the nth block 
    to be the hash of the n-1th block, the nth block, and delta other blocks chosen at random 
    from the buffer. In the last step, the extraction, the system outputs as the hash the last element in the buffer.


    High-security key derivation 128 MB space from ref implementation.

    The larger the time parameter, the longer the hash computation will take.
    The choice of time has an effect on the memory-hardness properties of the scheme: the larger time is, 
    the longer it takes to compute the function in small space.
*/

///
//Internal
//
mod error;
mod internal;
mod buffer;

//Our Implementation makes some assumptions
//We use 512 bits (64 bytes) blake2b.
//The size of each block is equal to the output size of the hash function H. 
//We use litte endian encoding

// use blake2_rfc::blake2b::{Blake2b, Blake2bResult};
use subtle::ConstantTimeEq;
use error::Error;
use num_bigint::BigUint;
use internal::Internal;
use buffer::SpaceHandler;
use blake2_rfc::blake2b::{Blake2bResult};

//
//Constants
//

pub const HASH_LEN: usize = 64;


//
//Helper functions
//

//Borrowed from https://github.com/briansmith/ring
//converts a unsigned 32bit integer to a big endien byte representation
#[inline(always)]
fn be_u8_from_u32(value: u32) -> [u8; 4] {
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
fn compare_ct(a: &[u8], b: &[u8]) -> Option<Error> {
    if a.len() != b.len() {
        return Some(Error::InvalidFormat);
    }

    if a.ct_eq(b).unwrap_u8() == 1 {
        None
    } else {
        return Some(Error::InvalidFormat);
    }
}

//
//Balloon
//

//new ballon instance with given space and time parameters
pub fn balloon(passy: &[u8], salty: &[u8], space: usize, time: usize, delta: usize) -> Result<Blake2bResult, Error> {

    //
    //Base Checks
    //

    //space must be greater than the digest length
    if space < 1 { return Err(Error::InvalidSpace) }
    //time must be greater than or equal to 
    if time < 1 { return Err(Error::InvalidTime) }
    //salt must be at least 4 bytes long
    if salty.len() < 4 { return Err(Error::InvalidSalt) }

    //
    //Main Variables
    //
    
    let mut internal = Internal {
        //alloc buf based on given space
        buffer:  SpaceHandler::allocate(space),
        last_block: None,
        counter: 0,
        space: space,
        time: time,
        delta: delta,
        has_mixed: false
    };

    //expand
    internal.expand(passy, salty);

    //mix
    internal.mix(salty);

    //output
    return internal.finalize();
}



//Verify BALLOON-BLAKE2b derived key in constant time.
pub fn verify(val: [u8; HASH_LEN], passy: &[u8], salty: &[u8], space: usize, time: usize, delta: usize) -> Result<bool, Error> {
    match balloon(passy, salty, space, time, delta) {
        //no errors continue
        Ok(res) => {
            //do we have a match
            match compare_ct(&res.as_bytes(), &val) {
                Some(_) => Ok(false),
                //no res means match
                None => Ok(true)
            }
        },
        
        Err(e) => Err(e)
    }
}




#[cfg(test)]
mod tests {
    use super::balloon;

    #[test]
    fn it_works() {
        let password = [0u8, 1u8, 2u8, 3u8, 0u8, 1u8, 2u8, 3u8];
        let salt = [0u8, 1u8, 2u8, 3u8, 3u8];
        //let test = balloon(&password, &salt, 8388608 , 3, 3);
        let test = balloon(&password, &salt, 16 , 20, 4);
        println!("{:?}", test.unwrap().as_bytes());

    }



}