use bitcoin::blockdata::transaction::Transaction;
use bitcoin::psbt::serialize::Deserialize;
use std::path::Path;

use leveldb::options::{Options, ReadOptions};
use leveldb::db::Database;
use leveldb::iterator::Iterable;
use bitcoin::hashes::hex::FromHex;

pub fn compress_transaction(tx: String, dot_bitcoin: String) -> Result<String, String> {
	let opt = Options::new();
	let path = Path::new(&dot_bitcoin).join("chainstate");
	println!("path = {}", path.display());
	let database = match Database::open(&path, &opt) {
		Ok(db) => db,
		Err(e) => return Err(e.to_string())
	};
	let read_opts = ReadOptions::new();
	let iter = database.iter(&read_opts);
	let bytes = Vec::from_hex(&tx).expect("could not convert from hex");
	let transaction = match Transaction::deserialize(&bytes) {
		Ok(transaction) => transaction,
		Err(error) => return Err(error.to_string()),
	};
	let mut unique_chars = Vec::new();
	for _ in 0..transaction.input.len() {
		unique_chars.push(0);
	}
	for entry in  iter.enumerate() {
        let (i, (key, _value)) = entry;
        println!("i = {}", i);
        let prefix = key[0];
        if prefix == 67 {
        	let sliced_key = &key[1..33];
			//let key_hex = hex::encode(&sliced_key);
	       	for i in 0..transaction.input.len() {
	       		let txid = transaction.input[i].previous_output.txid;
	       		for ii in 0..txid.len() {
	       			let ii_index = 31-ii;
	       			if txid[ii_index] != sliced_key[ii_index] {
	       				if ii > unique_chars[i] {
	       					unique_chars[i] = ii;
	       				}
	       				break
	       			}
	       		}
			}
        }
    
	}
	let mut TxIns: Vec<Vec<u8>> = Vec::new();
	for i in 0..unique_chars.len() {
		unique_chars[i] += 3;
		TxIns.push(transaction.input[i].previous_output.txid[(32-unique_chars[i])..32].to_vec());
		println!("unique_chars[{}] = {}", i, unique_chars[i]);
	}
	for i in 0..TxIns.len() {
		println!("TxIns[{}]: ", i);
		for ii in 0..TxIns[i].len() {
			print!("{}, ", TxIns[i][ii]);
		}
	}
	println!(";");


	return Ok(tx);
}

pub fn valid_transaction(tx: String) -> bool {

	let bytes = match Vec::from_hex(&tx) {
		Ok(bytes) => bytes,
		Err(error) => {
			println!("error = {}", error);
			return false
		}
	};
	println!("bytes: ");
	for byte in &bytes {
		print!("{:02x}, ", byte);
	}
	println!(";");
	 match Transaction::deserialize(&bytes) {
		Ok(_) => return true,
		Err(error) => {
			println!("error = {}", error);
			return false
		}
	};
} 