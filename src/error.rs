use secp256k1;
use bitcoin;
#[cfg(feature="gui")]
use iced;
use std::{error, fmt};
use std::convert::Infallible;
use bitcoin::SchnorrSigError;
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
    FromError(Infallible),
    SchnorrSigError(SchnorrSigError),
    BKE(bitcoin::util::key::Error),
    STDIOError(std::io::Error),
    ImageError(image::ImageError),
    TurboJPEGError(turbojpeg::Error),
    #[cfg(feature="gui")]
    Iced(iced::Error),
    NoTxOut,
    InvalidOutputCompressionCode,
    UnparsableCompression,
    CompressingTransactionError,
    UnParsableHuffmanTable
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

impl From<Infallible> for Error {
    fn from(e: Infallible) -> Error {
        Error::FromError(e)
    }
}

impl From<SchnorrSigError> for Error {
    fn from(e: SchnorrSigError) -> Error {
        Error::SchnorrSigError(e)
    }
}

impl From<bitcoin::util::key::Error> for Error {
    fn from(e: bitcoin::util::key::Error) -> Error {
        Error::BKE(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::STDIOError(e)
    }
}

impl From<image::ImageError> for Error {
    fn from(e: image::ImageError) -> Error {
        Error::ImageError(e)
    }
}

impl From<turbojpeg::Error> for Error {
    fn from(e: turbojpeg::Error) -> Error {
        Error::TurboJPEGError(e)
    }
}



#[cfg(feature="gui")]
impl From<iced::Error> for Error {
    fn from(e: iced::Error) -> Error {
        Error::Iced(e)
    }
}


impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        // match *self {
        //     _ => None
        // }
        None
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
            Error::BKE(ref e) => fmt::Display::fmt(e, f),
            Error::FromError(ref e) => fmt::Display::fmt(e, f),
            Error::SchnorrSigError(ref e) => fmt::Display::fmt(e, f),
            Error::STDIOError(ref e) => fmt::Display::fmt(e, f),
            Error::ImageError(ref e) => fmt::Display::fmt(e, f),
            Error::TurboJPEGError(ref e) => fmt::Display::fmt(e, f),
            #[cfg(feature="gui")]
            Error::Iced(ref e) => fmt::Display::fmt(e, f),
            Error::NoTxOut => f.write_str("No TxOut Found, Either Spent or Coinbase Transaction"),
            Error::InvalidOutputCompressionCode => f.write_str("Invalid Output Compression Code, Bad String Returned"),
            Error::UnparsableCompression => f.write_str("Unparsable Compression, Faild or Corupted Compression"),
            Error::CompressingTransactionError => f.write_str("Unable To Compress Transaction"),
            Error::UnParsableHuffmanTable => f.write_str("Unable To Parse Serilized Huffman Table")
        }
    }
}