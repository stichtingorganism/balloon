//! HashCash

//https://bitmessage.org/wiki/Proof_of_work
//https://github.com/imrehg/bmpow-rust

use mohan::{
    byteorder::{BigEndian, ByteOrder},
    hash::{blake256, H256},
};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

/// A single thread of Proof-of-Work calculation
///
/// Returns the nonce that satisfies the target requirement.
/// This value should be less than or equal to the target
pub fn hashcash(data: &[u8], difficulty: u8) -> (u64, H256) {
    for nonce in 0..u64::max_value() {
        // combine data and the nonce
        let buf = [data, &nonce.to_le_bytes()].concat();
        // salt is unique to the data, we take the first 8 bytes of its hash
        let salt = &blake256(&buf)[0..8];
        // work it baby
        let digest = blake256(&crate::balloon(&buf, &salt, 16, 20, 4).unwrap());
        if leading_zeros(digest.as_bytes()) >= difficulty {
            return (nonce, digest);
        }
        // if digest[..target as usize].iter().all(|x| *x == 0) {
        //     return (nonce, digest);
        // }
    }

    unreachable!()
}

pub fn hashcash_verify(data: &[u8], nonce: u64, difficulty: u8) -> bool {
    let buf = [data, &nonce.to_le_bytes()].concat();
    let salt = &blake256(&buf)[0..8];
    let digest = blake256(&crate::balloon(&buf, &salt, 16, 20, 4).unwrap());
    if leading_zeros(digest.as_bytes()) >= difficulty {
         return true;
    } else {
        return false;
    }
}

//https://github.com/maidsafe/resource_proof/blob/master/src/lib.rs
fn leading_zeros(data: &[u8]) -> u8 {
    let mut zeros = 0u8;
    for (count, i) in data.iter().enumerate() {
        zeros = i.leading_zeros() as u8 + (count as u8 * 8);
        if i.leading_zeros() < 8 {
            break;
        }
    }
    zeros
}

#[test]
fn test_hashcash() {
    //8 41.31 s , 10 85.31 s
    const DIFFICULTY: u8 = 10;
    use elapsed::measure_time;

    let (elapsed, _sum) = measure_time(|| {
        hashcash(b"organism", DIFFICULTY);
    });
    println!("elapsed = {}", elapsed);
    println!("elapsed seconds = {}", elapsed.seconds());
}

#[test]
fn test_hashcash2() {
    let (nonce, _) = hashcash(b"organism", 0);
    assert!(hashcash_verify(b"organism", nonce, 0));
}
