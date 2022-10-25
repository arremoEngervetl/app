// Coding conventions
// #![deny(non_upper_case_globals)]
// #![deny(non_camel_case_types)]
// #![deny(non_snake_case)]
// #![deny(unused_mut)]
// #![deny(missing_docs)]

extern crate bitcoin;
extern crate hex;
extern crate secp256k1;
extern crate bitcoincore_rpc;

pub mod compress;
pub mod error;
pub mod trellis;
pub mod image_compressor;
pub mod huffman_coding;
#[cfg(feature="gui")]
pub mod gui;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}