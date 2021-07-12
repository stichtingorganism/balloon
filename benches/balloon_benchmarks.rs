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

#[macro_use]
extern crate criterion;
extern crate balloon;

use balloon::balloon;
use criterion::Criterion;

fn key_derivation(c: &mut Criterion) {
    let password = [0u8, 1u8, 2u8, 3u8, 0u8, 1u8, 2u8, 3u8];
    let salt = [0u8, 1u8, 2u8, 3u8, 3u8];
    //let test = balloon(&password, &salt, 8388608 , 3, 3);
    //let test = balloon(&password, &salt, 16 , 20, 4)

    c.bench_function("Balloon hashing", move |b| {
        // b.iter(| | balloon(&password, &salt, 8388608 , 3, 4))
        b.iter(|| balloon(&password, &salt, 32, 40, 8))
    });
}

criterion_group!(benches, key_derivation);
criterion_main!(benches);
