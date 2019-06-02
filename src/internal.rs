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

//Balloon Hash main routines
//Each instance has an Internal Struct that is consumed on .finalize()

use crate::utilz::{HASH_LEN, to_num, be_u8_from_u32};
use crate::error::Error;
use crate::buffer::SpaceHandler;
use num_traits::cast::ToPrimitive;
use blake2b_simd::{Params, Hash};


//Internal state of a Balloon instance
pub struct Internal {
    //main buffer
    pub buffer: SpaceHandler<Hash>,
    //convineance 
    pub last_block: Option<Hash>,
    //counter (incrementing nonce) is required for proof of memory hardness
    pub counter: u32,
    //space is the number of digest-sized blocks in buffer (space cost).
    pub space: usize,
    //time is the number of rounds (time cost).
    pub time: usize,
    //delta is Number of dependencies per block.
    pub delta: usize,
    //has buffer been transformed
    pub has_mixed: bool
}


impl Internal {
    
    //
    // Step 1. Expansion    
    //
    pub fn expand(&mut self, passy: &[u8], salty: &[u8]) {

        // Using the state context, with a key.
        let mut hasher = Params::new().hash_length(HASH_LEN).to_state();

        //first block combines counter (0) + password + salt
        hasher.update(&be_u8_from_u32(self.counter));
        //increment count
        self.counter = self.counter + 1;
        hasher.update(passy);
        hasher.update(salty);

        //get the hash 
        self.last_block = Some(hasher.finalize());

        //add to buffer the first block
        self.buffer.insert(self.last_block.unwrap());

        //expand loop based on block size that fits space
        for _i in 1..self.space {
            //new hash context
            let mut squeeze = Params::new().hash_length(HASH_LEN).to_state();
            //add this count
            squeeze.update(&be_u8_from_u32(self.counter));
            //increment count
            self.counter = self.counter + 1;
            //add previous hash
            squeeze.update(self.last_block.unwrap().as_bytes());
            //change last block to this new one
            self.last_block = Some(squeeze.finalize());
            //add to buffer
            self.buffer.insert(self.last_block.unwrap());
        }
    }//end of expand
    
    //
    // Step 2. Mix buffer contents.
    //
    pub fn mix(&mut self, salty: &[u8]) {
        //outest loop is time controlled
        for t_step in 0..self.time {
            //inner loop is space bound
            for s_step in 0..self.space {
                //
                //Step 2a. Hash last and current blocks.
                //
                //new hash context
                let mut s_squeeze =  Params::new().hash_length(HASH_LEN).to_state();
                //hash count
                s_squeeze.update(&be_u8_from_u32(self.counter));
                //increment count
                self.counter = self.counter + 1;
                //prev block
                s_squeeze.update(self.last_block.unwrap().as_bytes());
                //this block
                s_squeeze.update(&self.buffer[s_step].as_bytes());

                //change last block to this new one
                self.last_block = Some(s_squeeze.finalize());
                //add to buffer
                self.buffer[s_step] = self.last_block.unwrap();

                //
                //Step 2b. Hash in pseudorandomly chosen blocks.
                //
                //this is bound by delta 
                for d_step in 0..self.delta {
                    //new hash context
                    let mut d_squeeze = Params::new().hash_length(HASH_LEN).to_state();
                    //hash count
                    d_squeeze.update(&be_u8_from_u32(self.counter));
                    //increment count
                    self.counter = self.counter + 1;
                    //salt
                    d_squeeze.update(salty);
                    //time index
                    d_squeeze.update(&be_u8_from_u32(t_step as u32));
                    //space index
                    d_squeeze.update(&be_u8_from_u32(s_step as u32));
                    //delta index
                    d_squeeze.update(&be_u8_from_u32(d_step as u32));

                    let idx_block = to_num(d_squeeze.finalize().as_bytes(), true);

                    //find index of other block
                    let other = (idx_block % self.space).to_usize().unwrap();

                    //reset hasher
                    d_squeeze = Params::new().hash_length(HASH_LEN).to_state();

                    //hash count
                    d_squeeze.update(&be_u8_from_u32(self.counter));
                    //increment count
                    self.counter = self.counter + 1;

                    //
                    d_squeeze.update(&self.buffer[s_step].as_bytes());
                    //
                    //d_squeeze.update(self.last_block.unwrap().as_bytes());

                    d_squeeze.update(&self.buffer[other].as_bytes());

                    //change last block to this new one
                    self.last_block = Some(d_squeeze.finalize());
                    //add to buffer
                    self.buffer[s_step] = self.last_block.unwrap();
                } 
            }//end of space loop
        }//end of time loop

        self.has_mixed = true;
    }//end of mix

    //
    // Step 3. Extract output from buffer.
    //
    pub fn finalize(&mut self) -> Result<Hash, Error> {
        // let bytes = self.buffer.len() * HASH_LEN;
        // let bytes_mb = (bytes as f64) * 0.000001; 
        // println!("Balloon Hash Buffer size {:?} bytes", bytes);
        // println!("Balloon Hash Buffer size {:?} mb", bytes_mb);
        //only finalize if mixing has occured
        if self.has_mixed {
            //hash last block
            Ok(Params::new().hash_length(HASH_LEN).hash(&self.buffer.back.pop().unwrap().as_bytes()))
            
        } else {
            Err(Error::FinalizeBeforeMix)
        }
    }//end of finalize
    

}
