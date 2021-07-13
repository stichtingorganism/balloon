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

use balloon::Balloon;
use blake3::Hasher as Blake3;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

#[cfg(feature = "cpb-bench")]
use criterion_cycles_per_byte::CyclesPerByte as Measurement;

#[cfg(not(feature = "cpb-bench"))]
use criterion::measurement::WallTime as Measurement;

fn bench(c: &mut Criterion<Measurement>) {
    let mut group = c.benchmark_group("balloon");

    let mut balloon = Balloon::<Blake3>::new(0, 0, 0);

    for s in &[1, 8, 16] {
        for t in &[1, 8, 16] {
            for d in 1..3 {
                balloon.reconfigure(*s, *t, d);
                group.bench_function(
                    BenchmarkId::new("test", format!("{}/{}/{}", s, t, d)),
                    |b| b.iter(|| balloon.process(b"super secret password", b"public salt")),
                );
            }
        }
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(Measurement);
    targets = bench
);
criterion_main!(benches);
