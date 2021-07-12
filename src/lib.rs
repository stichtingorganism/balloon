// Copyright 2021 Stichting Organism
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

extern crate num_bigint_dig as num_bigint;

mod error;
pub use error::Error;

mod buffer;
pub(crate) use buffer::SpaceHandler;

pub use blake3::Hash;

mod internal;
use internal::Internal;
use subtle::ConstantTimeEq;

//
//Balloon
//

//new ballon instance with given space and time parameters
pub fn balloon(
    passy: &[u8],
    salty: &[u8],
    space: u64,
    time: u64,
    delta: u64,
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

    //
    //Main Variables
    //

    let mut internal = Internal {
        //alloc buf based on given space
        buffer: SpaceHandler::allocate(space as usize),
        last_block: None,
        counter: 0,
        space: space,
        time: time,
        delta: delta,
        has_mixed: false,
    };

    //expand
    internal.expand(passy, salty);

    //mix
    internal.mix(salty);

    //output
    internal.finalize()
}

//Verify BALLOON-BLAKE2b derived key in constant time.
pub fn verify(
    val: &Hash,
    passy: &[u8],
    salty: &[u8],
    space: u64,
    time: u64,
    delta: u64,
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
    //use elapsed::measure_time;

    // #[test]
    // fn it_works() {
    //     let password = [0u8, 1u8, 2u8, 3u8, 0u8, 1u8, 2u8, 3u8];
    //     let salt = [0u8, 1u8, 2u8, 3u8, 3u8];
    //     //let test = balloon(&password, &salt, 8388608 , 3, 3);
    //     //let test = balloon(&password, &salt, 16 , 20, 4)

    //     let (_elapsed, _sum) = measure_time(|| {
    //         //space, time, delta
    //         //elapsed = 189.32 s
    //         //balloon(&password, &salt, 10000, 40, 4)
    //         // delta = 5
    //         // time_cost = 18
    //         // space_cost = 24
    //         //balloon(&password, &salt, 1000000, 5, 4)

    //         //s: 100, t: 50, d: 10 = 6 seconds on my mac
    //         //s: 400, t: 60, d: 10 = 25 seconds on my mac
    //         balloon(&password, &salt, 16, 20, 4)
    //     });

    //     //println!("elapsed = {}", elapsed);
    //     //println!("elapsed seconds = {}", elapsed.seconds());
    //     //println!("sum = {}", sum.unwrap().as_bytes());
    // }

    #[test]
    fn it_works2() {
        let password = [0u8, 1u8, 2u8, 3u8, 0u8, 1u8, 2u8, 3u8];
        let salt = [0u8, 1u8, 2u8, 3u8, 3u8];
        let test = balloon(&password, &salt, 24, 18, 5).unwrap();
        assert!(verify(&test, &password, &salt, 24, 18, 5).unwrap());
    }
}
