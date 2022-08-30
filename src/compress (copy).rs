use bitcoin::blockdata::transaction::Transaction;
use bitcoin::psbt::serialize::Deserialize;
use std::path::Path;

use leveldb::options::{Options, ReadOptions};
use leveldb::db::Database;
use leveldb::iterator::Iterable;
use bitcoin::hashes::hex::FromHex;
use trie_rs::TrieBuilder;

use hex;

fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
	return v1
    .iter()
    .zip(v2.iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();
}

fn extend(key: &Vec<u8>, value: &Vec<u8>) -> Vec<u8> {
	let mut result = Vec::new();
	let mut index = 0;
	for _ in 0..value.len() {
		result.push(key[index]);
		index = (index + 1) % key.len();
	}
	return result;
}

fn bytes_to_binary(x: &Vec<u8>) -> String {
	let mut x_string: String = String::new();
	for byte in x {
		let s_byte = format!("{:b}", byte);
		x_string += &format!("{:0>8}", s_byte);
	}
	return x_string
}

fn byte_to_binary(byte: &u8) -> String {
	//println!("byte = {}", byte);
	let s_byte = format!("{:b}", byte);
	//println!("bits = {}", format!("{:0>8}", s_byte));
	return format!("{:0>8}", s_byte);
}

pub fn compress_transaction(tx: String, dot_bitcoin: String) -> Result<String, String> {
	let block_height = 748554;
	//let mut builder = TrieBuilder::new();
	let mut older = 0;
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
	let mut deobfucation_key = Vec::new();
	for entry in  iter.enumerate() {
        let (i, (key, value)) = entry;
        let prefix = key[0];
        //println!("prefix = {}", prefix);
		println!("i = {}", i);
        if prefix == 0x0e {
        	let key_hex = hex::encode(&key);
        	println!("key_hex: {}", key_hex);
        	let value_hex = hex::encode(&value);
        	deobfucation_key = value.clone()[1..].to_vec();
        	println!("value_hex: {}", value_hex);
        	print!("key: ");
        	for byte in &key {
        		print!("{},", byte);
        	}
        	println!(";");
        	print!("value: ");
        	for byte in &value {
        		print!("{},", byte);
        	}
        	println!(";");
        } else if prefix == 0x43 {
			//let value_hex = hex::encode(&value);
			//println!("value_hex = {}", value_hex);
			let extended_key = extend(&deobfucation_key, &value);
			//let extended_key_hex = hex::encode(&extended_key);
			//println!("extended_key_hex = {}", &extended_key_hex);
			let dob_value = xor(&extended_key, &value);
			//let dob_value_hex = hex::encode(&dob_value);
			//println!("dob_value_hex = {}", dob_value_hex);
			//let dob_value_bytes: Vec<u8> = hex::decode("c0842680ed5900a38f35518de4487c108e3810e6794fb68b189d8b").expect("could not decode hex");
			let mut bytes = Vec::new();
			for byte in dob_value {
				if byte.leading_ones() > 0 {
					bytes.push(byte);
				} else {
					bytes.push(byte);
					break
				}

			}
			let mut variant = Vec::new();
			let mut carry = 0;
			variant.push(bytes[bytes.len()-1]);
			for iterator in 0..bytes.len()-1 {
				let iterator_val = (bytes.len()-2) -iterator;
				let byte = bytes[iterator_val];
				if (byte == 255) || (byte == 254 && carry == 1) {
					variant.push(0);
					carry = 1;
				} else {
					variant.push(byte+1+carry);
					carry = 0;
				}
			}
			if carry == 1 {
				variant.push(1);
			}
			variant.reverse();

			let mut variant_string = String::new();
			for byte in &variant {
				variant_string += &byte_to_binary(&byte)[1..8];
			}
			//let variant_hex = hex::encode(&variant);
			//println!("variant_hex = {}", variant_hex);
			variant_string = variant_string[..(variant_string.len()-1)].to_string();
			let height = i32::from_str_radix(&variant_string, 2).expect("Could not parse binary");
			if height < (block_height-1000) {
				//println!("i = {} accepted", i);
				//let mut cloned_key = key.clone();
		        //let sliced_key = &mut cloned_key[1..33];
		        //sliced_key.reverse();
				//let key_hex = hex::encode(&sliced_key);
				//println!("key_hex = {}", key_hex);
				older += 1;
				//builder.push(key_hex)
			}
			//println!("height: {}", height);
			


	       	//for i in 0..transaction.input.len() {
	       	//	let txid = transaction.input[i].previous_output.txid;
	       	//	for ii in 0..txid.len() {
	       	//		let ii_index = 31-ii;
	       	//		if txid[ii_index] != sliced_key[ii_index] {
	       	//			if ii > unique_chars[i] {
	       	//				unique_chars[i] = ii;
	       	//			}
	       	//			break
	       	//		}
	       	//	}
			//}
        }
	}
	//number of blocks older the 100 = 83442600
	//let trie = builder.build();
	println!("number of blocks older the 100 = {}", older);
	let mut tx_ins: Vec<Vec<u8>> = Vec::new();
	for i in 0..unique_chars.len() {
		unique_chars[i] += 3;
		tx_ins.push(transaction.input[i].previous_output.txid[(32-unique_chars[i])..32].to_vec());
		println!("unique_chars[{}] = {}", i, unique_chars[i]);
	}
	for i in 0..tx_ins.len() {
		println!("tx_ins[{}]: ", i);
		for ii in 0..tx_ins[i].len() {
			print!("{}, ", tx_ins[i][ii]);
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