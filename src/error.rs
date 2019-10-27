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

//Ballon errors
use failure::Fail;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Fail)]
pub enum ErrorKind {
    #[fail(display = "salt must be at least 4 bytes long")]
    InvalidSalt,
    #[fail(display = "space must be greater than the digest length")]
    InvalidSpace,
    #[fail(display = "time must be greater than or equal to 1")]
    InvalidTime,
    #[fail(display = "cannot finalize balloon before mixing")]
    FinalizeBeforeMix,
    #[fail(display = "invalid format is passed to Balloon")]
    InvalidFormat,
}
