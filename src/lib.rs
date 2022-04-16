#![deny(clippy::all)]
#![warn(clippy::pedantic)]
// #![warn(clippy::restriction)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
// pedantic
#![allow(clippy::many_single_char_names)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
// nursery
#![allow(clippy::use_self)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

mod array;
mod coefficient;
mod block;
mod poly;
mod generator;
pub mod config;
mod indcpa;
pub mod kem;

#[cfg(test)]
mod tests;
