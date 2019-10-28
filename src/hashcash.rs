//! HashCash

//https://bitmessage.org/wiki/Proof_of_work
//https://github.com/imrehg/bmpow-rust

use mohan::{
    byteorder::{ByteOrder, LittleEndian},
    hash::{
        blake256,
        H256
    }
};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::sync::Arc;


/// A single thread of Proof-of-Work calculation
///
/// Returns the nonce that satisfies the target requirement.
/// This value should be less than or equal to the target
pub fn hashcash(target: u64, data: &[u8]) -> (u64, H256) {
    for nonce in 0u64.. {
        let buf = [data, &nonce.to_le_bytes()].concat();
        let nonce = blake256(&buf)[0..8];
        let digest = blake256(&crate::balloon(&buf, &[1,1,1,1], 16, 20, 4).unwrap());
        if digest[..target as usize].iter().all(|x| *x == 0) {
            return (nonce, digest);
        }
    }

    unreachable!()
}

pub fn hashcash_verify(target: u64, nonce: u64, data: &[u8]) -> bool {
    let buf = [data, &nonce.to_le_bytes()].concat();
    let digest = blake256(&crate::balloon(&buf, &[1,1,1,1], 16, 20, 4).unwrap());
    if digest[..target as usize].iter().all(|x| *x == 0) {
            return true;
    } else {
        return false;
    }
}   


#[test]
fn test_hashcash() {
    use elapsed::measure_time;
   
    let (elapsed, _sum) = measure_time(|| {
        hashcash(1, b"organism");
    });
    println!("elapsed = {}", elapsed);
    println!("elapsed seconds = {}", elapsed.seconds());
}


#[test]
fn test_hashcash2() {
    let (nonce, _) = hashcash(2, b"organism");
    assert!(hashcash_verify(1, nonce, b"organism"));
}