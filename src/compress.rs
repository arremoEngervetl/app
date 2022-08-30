use bitcoin::blockdata::transaction::{Transaction, OutPoint, TxOut, TxIn};
use bitcoin::blockdata::witness::{Witness};
use bitcoin::blockdata::script::Script;
use bitcoin::psbt::serialize::Deserialize;
use bitcoin::Txid;

use secp256k1;

use bitcoin::hashes::hex::FromHex;

use bitcoincore_rpc::RpcApi;

use hex;

fn u16_to_2_bytes(x:u16) -> [u8;2] {
    let b1 : u8 = ((x >> 8) & 0xff) as u8;
    let b2 : u8 = (x & 0xff) as u8;
    return [b1, b2]
}

fn u32_to_4_bytes(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4]
}


//fn u64_to_8_bytes(x:u64) -> [u8;8] {
//	let b1 : u8 = ((x >> 56) & 0xff) as u8;
// 	let b2 : u8 = ((x >> 48) & 0xff) as u8;
// 	let b3 : u8 = ((x >> 40) & 0xff) as u8;
// 	let b4 : u8 = ((x >> 32) & 0xff) as u8;
// 	let b5 : u8 = ((x >> 24) & 0xff) as u8;
// 	let b6 : u8 = ((x >> 16) & 0xff) as u8;
// 	let b7 : u8 = ((x >> 8) & 0xff) as u8;
// 	let b8 : u8 = (x & 0xff) as u8;
// 	return [b1, b2, b3, b4, b5, b6, b7, b8]
//}

fn to_bits(x:u8) -> String {
	return format!("{:08b}", x);
}

fn to_varint(value: i64) -> Vec<u8> {
	let mut value_str = String::new();
	let binary = format!("{:b}", value);
	let mut index = 0;
	let varlen = (binary.len() as f64 / 7.0).ceil() as usize;
	let padding = (7*varlen)-binary.len();
	if varlen > 1 {
		value_str += "1";
		for _ in 0..padding {
			value_str += "0";
		};
		value_str += &binary[index..(7-padding)];
		index += 7-padding;
		for x in 1..varlen {
			if x+1 == varlen {
				value_str += "0";
			} else {
				value_str += "1";
			}
			value_str += &binary[index..index+7];
			index += 7;
		}
	} else {
		value_str += "0";
		for _ in 0..padding {
			value_str += "0";
		};
		value_str += &binary
	};

	println!("Value Str = {}", value_str);
	let mut result = Vec::new();
	for x in 0..varlen {
		let byte = u8::from_str_radix(&value_str[(x*8)..((x+1)*8)], 2).unwrap();
		result.push(byte);
	}
	return result
}

fn from_varint(tx: &Vec<u8>, oldindex: usize) -> (u64, usize) {
	let mut index = 0;
	let mut amount_str = String::new();
		loop {
			let byte = tx[oldindex+index];
			index += 1;
			let binary = format!("{:08b}", byte)[1..8].to_string();
			amount_str += &binary;
			if byte.leading_ones() == 0 {
				break
			}
		}

		println!("Amount Str = {}", amount_str);
		return (u64::from_str_radix(&amount_str, 2).unwrap(), index);
}



fn deserialize(tx_hex: String, rpc: bitcoincore_rpc::Client, trans: Transaction, txid_vec: Vec<Txid>) -> Result<String, String> {
	println!("----------------------------------");
	let tx: Vec<u8> = hex::decode(tx_hex).expect("uneaven hex");
	let mut index = 0;

	let control = to_bits(tx[index]);
	println!("{}", control);
	index += 1;

	let version: i32 = match &control[0..2] {
		"01" => 1,
		"10" => 2,
		"11" => 3,
		"00" => {
			index += 4;
			u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length")) as i32
		},
		_ => return Err("Invalid Version Compression Bit".to_string())
	};
	println!("Version = {}", version);

	let mut lock_time: u32 = 0;
	if &control[2..4] == "10" {
		let block_height = match rpc.get_block_count() {
			Ok(bh) => bh,
			Err(e) => {
				println!("error: {}", e);
				return Err(e.to_string());
			}
		};
		let first_lock: u32 = ((block_height as u32) / u32::pow(2,16)) * u32::pow(2,16);
		//TODO: Run throught 100 up and down from current bh
		let second_lock = u16::from_be_bytes(tx[index..index+2].try_into().expect("slice with incorrect length"));
		index += 2;
		lock_time = first_lock + second_lock as u32;
		println!("Locktime S = {}", lock_time);
	} else if &control[2..4] == "00" {
		lock_time = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
		println!("Locktime B = {}", lock_time);
		index += 4;
	} else if &control[2..4] == "01" {
		println!("Locktime 0 = {}", lock_time);
	} else {
		return Err("Invalid Locktime Compression Bit".to_string())
	}

	let input = to_bits(tx[index]);
	index += 1;
	let input_count: usize = match &input[0..2] {
		"00" => {
			let (i, smindex) = from_varint(&tx, index);
			index += smindex;
			i as usize
		},
		"01" => 1,
		"10" => 2,
		"11" => 3,
		_ => return Err("Invalid Input Compression Bit".to_string())
	};
	println!("Input Str = {}", input);
	println!("Input Count = {}", input_count);

	let mut global_sequence: u32 = 0;
	let mut sequence_vec = Vec::new();
	let mut global_sequence_var = true;
	println!("Sequence Str = {}", &input[2..6]);
	if &input[2..4] == "11" {
		global_sequence = match &input[4..6] {
			"01" => 0xFFFFFFFF,
			"10" => 0xFFFFFFFE,
			"11" => 0xFFFFFFF0,
			_ => return Err("Invalid Sequence Compression".to_string())
		}
	} else if &input[2..6] == "1000" {
		let sequence_byte = to_bits(tx[index]);
		println!("Sequence_byte = {}", sequence_byte);
		index += 1;
		for i in 0..input_count {
			let seq: u32 = match &sequence_byte[(i*2)..((i+1)*2)] {
				"01" => 0xFFFFFFFF,
				"10" => 0xFFFFFFFE,
				"11" => 0xFFFFFFF0,
				_ => return Err("Invalid Sequence Compression".to_string())
			};
			sequence_vec.push(seq);
		}
	} else if &input[2..6] == "0100" {
		global_sequence = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
		index += 4;
	} else {
		global_sequence_var = false;
	}

	let input_type = &input[6..8];



	
	let output = to_bits(tx[index]);
	index += 1;
	let output_count: usize = match &output[0..2] {
		"00" => {
			let (i, smindex) = from_varint(&tx, index);
			index += smindex;
			i as usize
		},
		"01" => 1,
		"10" => 2,
		"11" => 3,
		_ => return Err("Invalid Output Compression Bit".to_string())
	};
	println!("Output Str = {}", output);
	let output_type = &output[2..5];
	let mut output_type_identical = true;
	if output_type == "000" {
		output_type_identical = false;
	}
	println!("Output Count = {}", output_count);

	let mut tx_ins = Vec::new();
	for i in 0..input_count {

		let block_height = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
		println!("Input Height = {}", hex::encode(&tx[index..index+4]));
		index += 4;

		let block_index = u16::from_be_bytes(tx[index..index+2].try_into().expect("slice with incorrect length")) as usize;
		println!("Input Index = {}", hex::encode(&tx[index..index+2]));
		index += 2;

		let vout = tx[index] as u32;
		index += 1;

		let (script, witness) = match input_type {
			"01" => {
				let script_sig = &tx[index..index+71];
				index += 71;
				let pubkey = &tx[index..index+65];
				index += 65;
				let mut script_vec = Vec::new();
				script_vec.push(71);
				script_vec.extend(script_sig);
				script_vec.push(65);
				script_vec.extend(pubkey);
				let script = match Script::from_hex(&hex::encode(&script_vec)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				let witness_vec_vec: Vec<Vec<u8>> = Vec::new();
				let witness = Witness::from_vec(witness_vec_vec.clone());
				(script, witness)
			},
			"10" => {
				let script = match Script::from_hex("00") {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				let witness_vec_vec: Vec<Vec<u8>> = Vec::new();
				let witness = Witness::from_vec(witness_vec_vec.clone());
				(script, witness)
			},
			"11" => {
				let script = match Script::from_hex("00") {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				let witness_vec = &tx[index..index+65];
				index += 65;
				let mut witness_vec_vec: Vec<Vec<u8>> = Vec::new();
				witness_vec_vec.push(witness_vec.to_vec());
				let witness = Witness::from_vec(witness_vec_vec.clone());
				println!("wit = {}", hex::encode(witness.to_vec()[0].clone()));
				(script, witness)
			}
			_  => {
				let script_length = tx[index] as usize;
				index += 1;
				println!("Script length = {}", script_length);
				let script = match Script::from_hex(&hex::encode(&tx[index..index+script_length])) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				index += script_length;
				let witness_vec_vec: Vec<Vec<u8>> = Vec::new();
				let witness = Witness::from_vec(witness_vec_vec.clone());
				(script, witness)
			}
			
		};

		let sequence: u32 = match global_sequence_var {
			true if sequence_vec.len() == 0 => global_sequence,
			true => sequence_vec[i],
			false => {
				let sequence = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
				index += 4;
				sequence
			}
		};
		

		//let witness_count = tx[index];
		//index += 1;

		//let block_hash = match rpc.get_block_hash(block_height as u64) {
		//	Ok(hash) => hash,
		//	Err(e) => {
		//		println!("error = {}", e.to_string());
		//		return Err(e.to_string())
		//	}
		//};

		//let block_data = match rpc.get_block(&block_hash) {
		//	Ok(bd) => bd,
		//	Err(e) => {
		//		println!("error = {}", e.to_string());
		//		return Err(e.to_string())
		//	}
		//};

		//let txid = block_data.txdata[block_index].txid();
		let txid = txid_vec[i];
		println!("TxId = {}", txid);
		println!("Vout = {}", vout);
		println!("Script = {}", script);
		println!("Sequence = {}", sequence);

		
		//for _ in 0..witness_count {
//
//			let witness_length = tx[index] as usize;
//			println!("Witness Length = {}", witness_length);
//			index += 1;
//
//			println!("Witness = {}", hex::encode(&tx[index..index+witness_length]));
//			witness_vec.push(tx[index..index+witness_length].to_vec());
//			index += witness_length;
//
//		}

		let outpoint = OutPoint::new(txid, vout);
		let txin = TxIn {
			previous_output: outpoint,
			script_sig: script,
			sequence: sequence,
			witness: witness
		};
		tx_ins.push(txin);
	}
	
	let mut tx_outs = Vec::new();
	for i in 0..output_count {
		let (amount, smindex) = from_varint(&tx, index);
		index += smindex;
		println!("Amount = {}", amount);

		let mut output_type_str = output_type;
		let output_type_byte = to_bits(tx[index]).to_string();
		println!("test = {}", output_type_byte);
		if !output_type_identical {
			output_type_str = &output_type_byte[5..8];
			index += 1;
		}
		println!("output_?tr = {}", output_type_str);
		let script_pubkey = match output_type_str {
			"001" => {
				let bytes = &tx[index..index+20];
				index += 20;
				let mut script: Vec<u8> = Vec::new();
				script.push(169);
				script.push(20);
				script.extend(bytes);
				script.push(135);
				let script_pubkey = match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				script_pubkey
			},
			"010" => {
				let bytes = &tx[index..index+20];
				index += 20;
				let mut script: Vec<u8> = Vec::new();
				script.push(118);
				script.push(169);
				script.push(20);
				script.extend(bytes);
				script.push(136);
				script.push(172);
				let script_pubkey = match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				script_pubkey
			},
			"011" => {
				let bytes = &tx[index..index+65];
				index += 65;
				let mut script: Vec<u8> = Vec::new();
				script.push(65);
				script.extend(bytes);
				script.push(172);
				let script_pubkey = match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				script_pubkey
			},
			"100" => {
				let bytes = &tx[index..index+20];
				index += 20;
				let mut script: Vec<u8> = Vec::new();
				script.push(0);
				script.push(20);
				script.extend(bytes);
				let script_pubkey = match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				script_pubkey
			},
			"110" => {
				let bytes = &tx[index..index+32];
				index += 32;
				let mut script: Vec<u8> = Vec::new();
				script.push(81);
				script.push(32);
				script.extend(bytes);
				let script_pubkey = match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				script_pubkey
			},
			"111" => {
				let script_length = tx[index] as usize;
				println!("Script length = {}", script_length);
				index += 1;

				let script_pubkey = match Script::from_hex(&hex::encode(&tx[index..index+script_length])) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				println!("Script = {}", script_pubkey);
				index += script_length;
				script_pubkey
			}
			_ => return Err("Invalid Output Script Compression Byte".to_string())
		};
		println!("Script = {}", script_pubkey);
		println!("script = script = {}", script_pubkey == trans.output[i].script_pubkey);
		println!("script = {}", script_pubkey);
		println!("script = {}", trans.output[i].script_pubkey);
		
		let tx_out = TxOut {
			value: amount,
			script_pubkey: script_pubkey 
		};
		tx_outs.push(tx_out);
	};

	println!("input = {}", tx_ins == trans.input);
	println!("output = {}", tx_outs == trans.output);
	println!("lock_time = {}", lock_time == trans.lock_time);
	println!("lt = {}", lock_time);
	println!("tr.lt = {}", trans.lock_time);
	println!("v = {}", version == trans.version);
	
	let transaction = Transaction {
		version: version,
		lock_time: lock_time,
		input: tx_ins,
		output: tx_outs
	};
	//if &control[2..4] == "10" {
	//	loop {
	//		let valid: bool = match transaction.verify() {
	//			Ok(tx) => true,
	//			Err(error) => {
	//				println!("erorr = {}", error);
	//				false
	//			}
	//		};
	//		if valid {
	//			break
	//		};
	//		lock_time += u32::pow(2,16);
	//		println!("Locktime S = {}", lock_time);
	//	}
	//};
	println!("transaction == trans = {}", transaction == trans);
	println!("send");
	//match rpc.send_raw_transaction(&transaction) {
	//	Ok(r) => println!("{}", r),
	//	Err(e) => println!("{}", e)
	//};
	Ok("donet".to_string())
}

pub fn compress_transaction(tx: String, rpc: bitcoincore_rpc::Client) -> Result<String, String> {
	let mut compressed_transaction = Vec::new();
	let bytes = match Vec::from_hex(&tx) {
		Ok(bytes) => bytes,
		Err(error) => {
			println!("error = {}", error);
			return Err(error.to_string())
		}
	};
	println!("bytes: ");
	for byte in &bytes {
		print!("{:02x}, ", byte);
	}
	println!(";");
	let mut transaction = match Transaction::deserialize(&bytes) {
		Ok(transaction) => transaction,
		Err(error) => {
			return Err(error.to_string())
		}
	};

	let block_height = match rpc.get_block_count() {
		Ok(bh) => bh,
		Err(err) => return Err(err.to_string())
	};
	transaction.lock_time = 751723;
	//transaction.output.pop();
	//transaction.input.push(transaction.input[0].clone());
	//transaction.input.push(transaction.input[0].clone());
	//transaction.input[0].sequence = 0x0000000E;
	//transaction.input[1].sequence = 0x0000000E;
	//transaction.input[2].sequence = 0x0000000E;
	//transaction.input[3].sequence = 0x0000000E;

	println!("Version = {}", transaction.version as u8);
	
	let version_str = match transaction.version {
		1 => "01",
		2 => "10",
		3 => "11",
		_ => "00"
	};

	let limit = u32::pow(2, 16);
	let bhl = (block_height / limit as u64) * limit as u64;
	let ltl = ((transaction.lock_time / limit) * limit) as u64;
	println!("bhl - ltl = {}", bhl - ltl);
	let lock_time_str = match transaction.lock_time {
		0 => "01",
		_ if bhl >= ltl && bhl - ltl < 100  => "10",
		_ if ltl >= bhl && ltl - bhl < 100  => "10",
		_ => "00"
	};
	println!("bhl = {}", bhl);
	println!("lock_time_str = {}", lock_time_str);

	let mut control_str = String::new();
	control_str += version_str;
	control_str += lock_time_str;
	control_str += "0000";

	let control: u8 = u8::from_str_radix(&control_str, 2).unwrap();
	println!("Control = {}", control);
	compressed_transaction.push(control);

	if version_str == "00" {
		compressed_transaction.extend(u32_to_4_bytes(transaction.version as u32));
	}

	println!("Locktime = {}", transaction.lock_time);
	if lock_time_str == "00" {
		let lock_time = u32_to_4_bytes(transaction.lock_time);
		compressed_transaction.extend(lock_time);
		println!("Locktime L = {}", transaction.lock_time);
	} else if lock_time_str == "10" {
		let second_lock = (transaction.lock_time % limit) as u16;
		let lock_time = u16_to_2_bytes(second_lock);
		compressed_transaction.extend(lock_time);
		println!("Locktime S = {}", second_lock);
	} else if lock_time_str == "01" {
		println!("Locktime 0");
	}
	

	let mut input_str = String::new();
	input_str += match transaction.input.len() {
		1 => "01",
		2 => "10",
		3 => "11",
		_ => "00"
	};
	

	let mut sequence_vec = Vec::new();
	let mut sequence_small = true;
	for i in 0..transaction.input.len() { 
		let sequence_str_temp = match transaction.input[i].sequence {
			0xFFFFFFFF => "01".to_string(),
			0xFFFFFFFE => "10".to_string(),
			0xFFFFFFF0 => "11".to_string(),
			i => {
				sequence_small = false;
				i.to_string()
			}
		};
		sequence_vec.push(sequence_str_temp);
	}
	let mut v = sequence_vec.clone();
	v.sort_unstable();
	v.dedup();
	let mut sequence_str = "0000".to_string();
	let mut sequence_byte = String::new();
	if v.len() == 1 {
		if sequence_small {
			sequence_str = "11".to_string()+&v[0];
		} else {
			sequence_str = "0100".to_string();
		}
	} else if sequence_small {
		if input_str != "00" {
			sequence_str = "1000".to_string();
			for i in 0..transaction.input.len() {
				sequence_byte += &sequence_vec[i];
			}
			for _ in 0..4-transaction.input.len() {
				sequence_byte += "00";
			}
		}
		// else {
		//	sequence_str = "0011".to_string();
		//}
	}

	println!("Sequence Str = {}", sequence_str);
	println!("Sequence Byte = {}", sequence_byte);
	input_str += &sequence_str;


	let mut input_type_str = "00";
	let mut input_identical = true;

	let script = transaction.input[0].script_sig.as_bytes();
	if script.len() == 138 && script[0] == 71 && script[72] == 65 {
		input_type_str = "01"
	} else if script.len() == 0 {
		if transaction.input[0].witness.len() == 1 {
			input_type_str = "11"
		} else {
			input_type_str = "10"
		}
	}

	for i in 0..transaction.input.len() {
		if input_type_str == "01" && input_identical {
			let script = transaction.input[i].script_sig.as_bytes();
			if !(script.len() == 138 && script[0] == 71 && script[72] == 65) {
				input_type_str = "00";
				input_identical = false;
			}
		} else if input_type_str == "10" && input_identical {
			if transaction.input[i].witness.len() != 2 {
				input_type_str = "00";
				input_identical = false;
			} 
		} else if input_type_str == "11" && input_identical {
			if transaction.input[i].witness.len() != 1 {
				input_type_str = "00";
				input_identical = false;
			} 
		}
		if !input_identical {
			break
		}
	}
	
	input_str += input_type_str;
	let input: u8 = u8::from_str_radix(&input_str, 2).unwrap();
	println!("Input Str = {}", input_str);
	compressed_transaction.push(input);
	if &input_str[0..2] == "00" {
		compressed_transaction.extend(to_varint(transaction.input.len() as i64));
		println!("Input Count = {}", transaction.input.len() as i64);
	}
	if sequence_str == "0100" {
		compressed_transaction.extend(u32_to_4_bytes(transaction.input[0].sequence));
	} else if sequence_str == "1000" {
		compressed_transaction.push(u8::from_str_radix(&sequence_byte, 2).unwrap());
	}

	let mut output_str = String::new();
	output_str += match transaction.output.len() {
		1 => "01",
		2 => "10",
		3 => "11",
		_ => "00"
	};
	let mut output_type_identical = true;
	let script = &transaction.output[0].script_pubkey;
	let mut output_type_str = "111";
	if script.is_p2sh() {
		output_type_str = "001"
	} else if script.is_p2pkh() {
		output_type_str = "010"
	} else if script.is_p2pk() {
		output_type_str = "011"
	} else if script.is_v0_p2wpkh() {
		output_type_str = "100"
	} else if script.is_v0_p2wsh() {
		output_type_str = "101"
	} else if script.is_v1_p2tr() {
		output_type_str = "110"
	}
	for i in 0..transaction.output.len() {
		if !output_type_identical {
			break
		}
		let script = &transaction.output[i].script_pubkey;
		if script.is_p2sh() {
			if !(output_type_str == "001") {
				output_type_identical = false;
			}
		} else if script.is_p2pkh() {
			if !(output_type_str == "010") {
				output_type_identical = false;
			}
		} else if script.is_p2pk() {
			if !(output_type_str == "011") {
				output_type_identical = false;
			}
		} else if script.is_v0_p2wpkh() {
			if !(output_type_str == "100") {
				output_type_identical = false;
			}
		} else if script.is_v0_p2wsh() {
			if !(output_type_str == "101") {
				output_type_identical = false;
			}
		} else if script.is_v1_p2tr() {
			if !(output_type_str == "110") {
				output_type_identical = false;
			}
		} else {
			if !(output_type_str == "111") {
				output_type_identical = false;
			}
		}
	}
	
	if output_type_identical {
		output_str += output_type_str;
	} else {
		output_str += "000";
	}
	
	output_str += "000";
	let output: u8 = u8::from_str_radix(&output_str, 2).unwrap();
	println!("Output Str = {}", output_str);
	compressed_transaction.push(output);

	if &output_str[0..2] == "00" {
		compressed_transaction.extend(to_varint(transaction.output.len() as i64));
		println!("Output Count = {}", transaction.output.len() as i64);
	}

	let mut txid_vec = Vec::new();
	
	for i in 0..transaction.input.len() {
		let (height, index) = ([0,0,14,16],[19,91]);
		//let (height, index) = match rpc.get_transaction(&transaction.input[i].previous_output.txid, Some(true)) {
		//	Ok(blob) => {
		//		let h = match blob.info.blockheight {
		//			Some(h) => u32_to_4_bytes(h),
		//			None => return Err("Could not find height".to_string())
		//		};
		//		let i = match blob.info.blockindex {
		//			Some(i) => u16_to_2_bytes(i as u16),
		//			None => return Err("Could not find index".to_string())
		//		};
		//		(h, i)
		//	},
		//	Err(error) => return Err(error.to_string())
		//};
		
		
		compressed_transaction.extend(height);
		println!("Height = {}", hex::encode(height));

		compressed_transaction.extend(index);
		println!("Index = {}", hex::encode(index));

		txid_vec.push(transaction.input[i].previous_output.txid);
		println!("TxId = {}", transaction.input[i].previous_output.txid);

		compressed_transaction.push(transaction.input[i].previous_output.vout as u8);
		println!("Vout = {}", transaction.input[i].previous_output.vout);

		println!("Script Hex = {}", hex::encode(transaction.input[i].script_sig.as_bytes()));
		println!("Script = {}", transaction.input[i].script_sig);
		let script = transaction.input[i].script_sig.as_bytes();
		match &input_str[6..8] {
			"01" => {
				let script_sig = &script[1..72];
				let pubkey = &script[73..138];
				compressed_transaction.extend(script_sig);
				compressed_transaction.extend(pubkey);
			},
			"10" => {
				println!("No Script");
				let signature = secp256k1::ecdsa::Signature::from_der(&transaction.input[i].witness.to_vec()[0]);


				//println!("sig = {}", signature);
				//compressed_transaction.push(transaction.input[i].witness.to_vec()[x].len() as u8);
			},
			"11" => {
				println!("post TR");
				println!("wit = {}", hex::encode(transaction.input[i].witness.to_vec()[0].clone()));
				compressed_transaction.extend(transaction.input[i].witness.to_vec()[0].clone());
			}
			_ => {
				compressed_transaction.push(transaction.input[i].script_sig.len() as u8);
				println!("Script length = {}", transaction.input[i].script_sig.len() as u8);
				
				compressed_transaction.extend(transaction.input[i].script_sig.to_bytes());
				println!("Script = {}", transaction.input[i].script_sig);
			}
		}

		if sequence_str == "0000" {
			compressed_transaction.extend(u32_to_4_bytes(transaction.input[i].sequence));
			println!("Sequence = {}", transaction.input[i].sequence);
		} 

		//compressed_transaction.push(transaction.input[i].witness.to_vec().len() as u8);
		//println!("Witness Count = {}", transaction.input[i].witness.to_vec().len() as u8);

		//for x in 0..transaction.input[i].witness.to_vec().len() {
		//	compressed_transaction.push(transaction.input[i].witness.to_vec()[x].len() as u8);
		//	println!("Witness length = {}", transaction.input[i].witness.to_vec()[x].len() as u8);
//
//			compressed_transaction.extend(transaction.input[i].witness.to_vec()[x].clone());
//			println!("Witness = {}", hex::encode(transaction.input[i].witness.to_vec()[x].clone()));
//		}
	}
	
	for i in 0..transaction.output.len() {
		compressed_transaction.extend(to_varint(transaction.output[i].value as i64));

		//compressed_transaction.extend(u64_to_8_bytes(transaction.output[i].value));
		println!("Amount = {}", transaction.output[i].value);
		let script = &transaction.output[i].script_pubkey;
		println!("Script = {}", script);
		println!("Script Hex = {}", hex::encode(transaction.output[i].script_pubkey.as_bytes()));
		let mut output_type_str = "111";
		if script.is_p2sh() {
			println!("p2sh");
			output_type_str = "001"
		} else if script.is_p2pkh() {
			println!("p2pkh");
			output_type_str = "010"
		} else if script.is_p2pk() {
			println!("p2pk");
			output_type_str = "011"
		} else if script.is_v0_p2wpkh() {
			println!("v0_p2wpkh");
			output_type_str = "100"
		} else if script.is_v0_p2wsh() {
			println!("v0_p2wsh");
			output_type_str = "101"
		} else if script.is_v1_p2tr() {
			println!("v1_p2tr");
			output_type_str = "110"
		} else {
			println!("Unknow script");
		}
		println!("output type = {}", output_type_str);
		let scriptb = &script.to_bytes();
		match output_type_str {
			"001" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()-1].to_vec())
			},
			"010" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
				}
				compressed_transaction.extend(scriptb[3..scriptb.len()-2].to_vec())
			},
			"011" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
				}
				compressed_transaction.extend(scriptb[1..scriptb.len()-1].to_vec())
			},
			"100" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec())
			},
			"110" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec())
			},
			"111" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
				}
				compressed_transaction.push(transaction.output[i].script_pubkey.len() as u8);
				println!("Script Length = {}", transaction.output[i].script_pubkey.len() as u8);

				compressed_transaction.extend(transaction.output[i].script_pubkey.to_bytes());
				println!("Script = {}", transaction.output[i].script_pubkey);
				println!("Script Hex = {}", hex::encode(transaction.output[i].script_pubkey.to_bytes()));
			}
			_ => return Err("Unknown error Compressing Output Script".to_string())
		};
	}
	//panic!("Script Encoding");

	let result = hex::encode(compressed_transaction);
	println!("len tx = {}", tx.len());
	println!("len result = {}", result.len());
	println!("tx = {}", tx);
	println!("result = {}", result);

	return deserialize(result, rpc, transaction, txid_vec);
}

pub fn valid_transaction(tx: String) -> String {

	let bytes = match Vec::from_hex(&tx) {
		Ok(bytes) => bytes,
		Err(error) => {
			return error.to_string()
		}
	};
	 match Transaction::deserialize(&bytes) {
		Ok(_) => return "".to_string(),
		Err(error) => {
			return error.to_string()
		}
	};
} 