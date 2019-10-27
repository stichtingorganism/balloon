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

//Buffer Manager
//Fixed Length AppendOnly Memory Buffer

use std::ops::{Index, IndexMut};

//Buffer backed by a Vec for now
#[derive(Debug, Clone)]
pub struct SpaceHandler<T> {
    pub back: Vec<T>,
}

impl<T> SpaceHandler<T> {
    //create a new buffer with fixed size
    pub fn allocate(len: usize) -> SpaceHandler<T> {
        SpaceHandler {
            back: Vec::with_capacity(len),
        }
    }

    //add an element, return index
    pub fn insert(&mut self, item: T) {
        self.back.push(item)
    }

    //retrieve an element from given index
    //pub fn get(&self, index: usize) -> Option<&T> { self.back.get(index) }

    //retrieve an element from given index and mutate
    //pub fn get_mut(&mut self, index: usize) -> Option<&mut T> { self.back.get_mut(index) }

    //clear underlying memory slab
    //pub fn clear(&mut self) { self.back.clear() }
    //pub fn is_empty(&self) -> bool { self.back.is_empty() }
    pub fn len(&self) -> usize {
        self.back.len()
    }
}

//
//Implement index trait
//

impl<T> Index<usize> for SpaceHandler<T> {
    type Output = T;

    fn index(&self, key: usize) -> &Self::Output {
        &self.back[key]
    }
}

impl<T> IndexMut<usize> for SpaceHandler<T> {
    fn index_mut(&mut self, key: usize) -> &mut T {
        &mut self.back[key]
    }
}
