use secp256k1;
use bitcoin;

use std::{error, fmt};
#[derive(Debug)]
pub enum Error {
    /// Error from libsecp
    Secp(secp256k1::Error),
    Bitcoin(bitcoin::Error),
    Hex(bitcoin::hashes::hex::Error),
    BCE(bitcoin::consensus::encode::Error),
    BBS(bitcoin::blockdata::script::Error),
    BitcoinRpc(bitcoincore_rpc::Error),
    EcdsaSigError(bitcoin::EcdsaSigError),
    BUS(bitcoin::util::sighash::Error),
    NoTxOut,
    InvalidOutputCompressionCode,
    UnparsableCompression,
    CompressingTransactionError
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp(e)
    }
}

impl From<bitcoin::Error> for Error {
    fn from(e: bitcoin::Error) -> Error {
        Error::Bitcoin(e)
    }
}

impl From<bitcoin::hashes::hex::Error> for Error {
    fn from(e: bitcoin::hashes::hex::Error) -> Error {
        Error::Hex(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error {
        Error::BCE(e)
    }
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Error {
        Error::BitcoinRpc(e)
    }
}

impl From<bitcoin::blockdata::script::Error> for Error {
    fn from(e: bitcoin::blockdata::script::Error) -> Error {
        Error::BBS(e)
    }
}

impl From<bitcoin::EcdsaSigError> for Error {
    fn from(e: bitcoin::EcdsaSigError) -> Error {
        Error::EcdsaSigError(e)
    }
}

impl From<bitcoin::util::sighash::Error> for Error {
    fn from(e: bitcoin::util::sighash::Error) -> Error {
        Error::BUS(e)
    }
}


impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            _ => None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Secp(ref e) => error::Error::description(e),
            Error::Bitcoin(ref e) => error::Error::description(e),
            Error::Hex(ref e) => error::Error::description(e),
            Error::BCE(ref e) => error::Error::description(e),
            Error::BBS(ref e) => error::Error::description(e),
            Error::BitcoinRpc(ref e) => error::Error::description(e),
            Error::EcdsaSigError(ref e) => error::Error::description(e),
            Error::BUS(ref e) => error::Error::description(e),
            Error::NoTxOut => "No TxOut Found, Either Spent or Coinbase Transaction",
            Error::InvalidOutputCompressionCode => "Invalid Output Compression Code, Bad String Returned",
            Error::UnparsableCompression => "Unparsable Compression, Faild or Corupted Compression",
            Error::CompressingTransactionError => "Unable To Compress Transaction"
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
            Error::Bitcoin(ref e) => fmt::Display::fmt(e, f),
            Error::Hex(ref e) => fmt::Display::fmt(e, f),
            Error::BCE(ref e) => fmt::Display::fmt(e, f),
            Error::BBS(ref e) => fmt::Display::fmt(e, f),
            Error::BitcoinRpc(ref e) => fmt::Display::fmt(e, f),
            Error::EcdsaSigError(ref e) => fmt::Display::fmt(e, f),
            Error::BUS(ref e) => fmt::Display::fmt(e, f),
            _ => f.write_str(&self.to_string())
        }
    }
}