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

//Ballon errors

use std::{fmt, error};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    //Invalid format is passed to function
    InvalidSalt,
    InvalidSpace,
    InvalidTime,
    FinalizeBeforeMix,
    InvalidFormat
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidSalt => "salt must be at least 4 bytes long",
            Error::InvalidSpace => "space must be greater than the digest length",
            Error::InvalidTime => "time must be greater than or equal to 1",
            Error::FinalizeBeforeMix => "cannot finalize balloon before mixing",
             Error::InvalidFormat => "invalid format is passed to Balloon"
        })
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::InvalidSalt => "salt must be at least 4 bytes long",
            Error::InvalidSpace => "space must be greater than the digest length",
            Error::InvalidTime => "time must be greater than or equal to 1",
            Error::FinalizeBeforeMix => "cannot finalize balloon before mixing",
             Error::InvalidFormat => "invalid format is passed to Balloon"
        }
    }
}