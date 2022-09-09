use bitcoin::blockdata::transaction::{Transaction, OutPoint, TxOut, TxIn};
use bitcoin::blockdata::witness::{Witness};
use bitcoin::blockdata::script::Script;
use bitcoin::psbt::serialize::Deserialize;
use bitcoin::Txid;

use bitcoin::network::constants::Network;
use bitcoin::blockdata::script::Instruction;
use secp256k1::Secp256k1;
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

		return (u64::from_str_radix(&amount_str, 2).unwrap(), index);
}

fn deserialize(tx_hex: &String, rpc: &bitcoincore_rpc::Client, trans: Transaction, txid_vec: Vec<Txid>) -> Result<String, String> {
	println!("D----------------------------------");
	let tx: Vec<u8> = hex::decode(tx_hex).expect("uneaven hex");
	let mut index = 0;

	//Grab Controll bit (vvl)
	let control = to_bits(tx[index]);
	println!("Control = {}", control);
	index += 1;

	//Parse Version
	let version: i32 = match &control[0..2] {
		"01" => 1,
		"10" => 2,
		"11" => 3,
		"00" => {
			let vers = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length")) as i32;
			println!("Version = {}", hex::encode(&tx[index..index+4]));
			index += 4;
			vers
		},
		_ => return Err("Invalid Version Compression Bit".to_string())
	};

	//Parse Lock Time
	let mut lock_time: u32 = 0;
	match &control[2..4] {
		"11" => {
			//If lock time was not zero grab the next 4 bytes
			let second_lock = u16::from_be_bytes(tx[index..index+2].try_into().expect("slice with incorrect length"));
			println!("Lock Time S = {}", hex::encode(&tx[index..index+2]));
			index += 2;
			lock_time = second_lock as u32;
		},
		"10" => {
			let (lock_time_tmp, smindex) = from_varint(&tx, index);
			index += smindex;
			lock_time = lock_time_tmp as u32;
			println!("Lock Time = {}", lock_time);
		},
		"00" => {
		},
		_ => return Err("Invalid Locktime Compression Bit".to_string())
	}

	//Grab Input Byte
	let input = to_bits(tx[index]);
	println!("Input = {}", input);
	index += 1;

	//Parse input count
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

	//Parse Signature
	let mut global_sequence: u32 = 0;
	let mut sequence_vec = Vec::new();
	let mut global_sequence_var = true;
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
		println!("0100 Sequence = {}", hex::encode(&tx[index..index+4]));
		index += 4;
	} else {
		global_sequence_var = false;
	}

	//Parse Input Type
	let input_type = &input[6..7];
	let mut input_type_identical = true;
	if &input[7..8] == "0" {
		input_type_identical = false;
	}

	//Get Output Byte
	let output = to_bits(tx[index]);
	println!("Output = {}", output);
	index += 1;

	//Parse Output Count
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

	//Parse Output Type
	let output_type = &output[2..5];
	let mut output_type_identical = true;
	if output_type == "000" {
		output_type_identical = false;
	}

	let mut tx_ins = Vec::new();
	let mut recoverable_signatures = Vec::new();
	let mut half_finished_inputs = Vec::new();
	for i in 0..input_count {

		let block_height = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
		println!("Block Height = {}", hex::encode(&tx[index..index+4]));
		index += 4;

		let block_index = u16::from_be_bytes(tx[index..index+2].try_into().expect("slice with incorrect length")) as usize;
		println!("Block Index = {}", hex::encode(&tx[index..index+2]));
		index += 2;

		//Get vout
		let (vout, smindex) = from_varint(&tx, index);
		println!("Vout = {}", vout);
		index += smindex;

		//Input Type
		let mut input_type_str = input_type;
		let input_type_byte = to_bits(tx[index]).to_string();
		if !input_type_identical {
			input_type_str = &input_type_byte[7..8];
			index += 1;
		}

		let mut recoverable_sigs = Vec::new();
		//Get Script and Witness
		let (script, witness) = match input_type_str {
			"1" => {
				//"1" input type is a compressed compact signature
				let script = Script::new();
				let bytes = &tx[index..index+64];
				println!("01 10 11 Sig = {}", hex::encode(&tx[index..index+64]));
				index += 64;
				let recoverable_signature_0 = secp256k1::ecdsa::RecoverableSignature::from_compact(&bytes, secp256k1::ecdsa::RecoveryId::from_i32(0).expect("Could not create RecoveryId")).expect("Could Not Recover Signature");
				let recoverable_signature_1 = secp256k1::ecdsa::RecoverableSignature::from_compact(&bytes, secp256k1::ecdsa::RecoveryId::from_i32(1).expect("Could not create RecoveryId")).expect("Could Not Recover Signature");
				recoverable_sigs.push(recoverable_signature_0);
				recoverable_sigs.push(recoverable_signature_1);
				let witness_vec_vec: Vec<Vec<u8>> = Vec::new();
				let witness = Witness::from_vec(witness_vec_vec.clone());
				half_finished_inputs.push(i);
				(script, witness)
			},
			_  => {
				//"0" input type is custom script/witness
				let script_length = tx[index] as usize;
				println!("Script Length = {}", script_length);
				index += 1;

				let script = match Script::from_hex(&hex::encode(&tx[index..index+script_length])) {
					Ok(ss) => ss,
					Err(e) => return Err(e.to_string())
				};
				println!("Script = {}", hex::encode(&tx[index..index+script_length]));
				index += script_length;

				let witness_count = tx[index] as usize;
				println!("Witnesses Length = {}", witness_count);
				index += 1;

				let mut witness_vec_vec: Vec<Vec<u8>> = Vec::new();
				for _ in 0..witness_count {
					let witness_len = tx[index] as usize;
					println!("Witness Length = {}", witness_len);
					index += 1;

					let witness = &tx[index..index+witness_len];
					println!("Witness = {}", hex::encode(&tx[index..index+witness_len]));
					index += witness_len;

					witness_vec_vec.push(witness.to_vec());
				}
				
				let witness = Witness::from_vec(witness_vec_vec.clone());
				(script, witness)
			}
			
		};

		//sequence was parsed above but might be of custom type
		//true no sequ vec = all sequences are the same displayed as 2 bits of the sequence byte or as 4 bytes directly after the input
		//true sequence vec = all sequences are minimal but not identical grab from a vec
		let sequence: u32 = match global_sequence_var {
			true if sequence_vec.len() == 0 => global_sequence,
			true => sequence_vec[i],
			false => {
				let sequence = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
				println!("0000 Sequence = {}", hex::encode(&tx[index..index+4]));
				index += 4;
				sequence
			}
		};
		
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
		//TODO: Grab txid for testing
		let txid = txid_vec[i];


		recoverable_signatures.push(recoverable_sigs);

		//assemble OutPoint
		let outpoint = OutPoint::new(txid, vout as u32);
		let txin = TxIn {
			previous_output: outpoint,
			script_sig: script,
			sequence: sequence,
			witness: witness
		};
		tx_ins.push(txin);
	}
	
	let mut tx_outs = Vec::new();
	for _ in 0..output_count {
		//Grab varint amount
		let (amount, smindex) = from_varint(&tx, index);
		println!("Amount = {}", amount);
		index += smindex;

		//If output type is not identical grab as the next byte
		let mut output_type_str = output_type;
		let output_type_byte = to_bits(tx[index]).to_string();
		if !output_type_identical {
			output_type_str = &output_type_byte[5..8];
			println!("Output Type = {}", output_type_str);
			index += 1;
		}
		let script_pubkey = match output_type_str {
			"001" => {
				//p2sh
				let bytes = &tx[index..index+20];
				println!("Script = {}", hex::encode(&tx[index..index+20]));
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
				//p2pkh
				let bytes = &tx[index..index+20];
				println!("Script = {}", hex::encode(&tx[index..index+20]));
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
				//p2pk
				let bytes = &tx[index..index+65];
				println!("Script = {}", hex::encode(&tx[index..index+20]));
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
				//v0_p2wpkh
				let bytes = &tx[index..index+20];
				println!("Script = {}", hex::encode(&tx[index..index+20]));
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
			"101" => {
				//v0_p2wsh
				let bytes = &tx[index..index+32];
				println!("Script = {}", hex::encode(&tx[index..index+20]));
				index += 32;
				let mut script: Vec<u8> = Vec::new();
				script.push(0);
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
			"110" => {
				//p2tr
				let bytes = &tx[index..index+32];
				println!("Script = {}", hex::encode(&tx[index..index+20]));
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
				//Custom Script
				let script_length = tx[index] as usize;
				println!("Script Length = {}", script_length);
				index += 1;

				let script_pubkey = match Script::from_hex(&hex::encode(&tx[index..index+script_length])) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				println!("Script = {}", hex::encode(&tx[index..index+script_length]));
				index += script_length;
				script_pubkey
			}
			_ => return Err("Invalid Output Script Compression Byte".to_string())
		};
		
		let tx_out = TxOut {
			value: amount,
			script_pubkey: script_pubkey 
		};
		tx_outs.push(tx_out);
	};

	//Assemble Transaction
	let mut transaction = Transaction {
		version: version,
		lock_time: lock_time,
		input: tx_ins.clone(),
		output: tx_outs
	};

	if &control[2..4] == "11" {
		let script_pubkey = match rpc.get_tx_out(&tx_ins[0].previous_output.txid, tx_ins[0].previous_output.vout, Some(true)) {
			Ok(r) => match r {
				Some(rs) => match rs.script_pub_key.script() {
					Ok(pk) => pk,
					Err(err) => {
						println!("error1 = {}", err);
						return Err(err.to_string());
					}
				},
				None => {
					println!("error = {}", "Cannot find Tx Out");
					return Ok("Cannot find TX Out".to_string());
				}
			},
			Err(err) => {
				println!("error2 = {}", err);
				return Err(err.to_string());
			}
		};
		println!("sc = {}", script_pubkey);

		let pow16 = u32::pow(2, 16);
		loop {
			let sig_hash = transaction.signature_hash(0, &script_pubkey, 0x1 as u32);
			println!("sig_hash  = {}", sig_hash);
			transaction.lock_time += pow16;
			if transaction.lock_time > 1000000 {
				break
			}
		}
	}

	if half_finished_inputs.len() > 0 {
		let i = half_finished_inputs[0];
		println!("First Half Finished Input = {}", i);
		let script_pubkey = match rpc.get_tx_out(&tx_ins[i].previous_output.txid, tx_ins[i].previous_output.vout, Some(false)) {
			Ok(r) => match r {
				Some(rs) => match rs.script_pub_key.script() {
					Ok(pk) => pk,
					Err(err) => {
						println!("error = {}", err);
						return Err(err.to_string());
					}
				},
				None => {
					println!("error = {}", "Cannot find Tx Out");
					return Ok("Cannot find TX Out(not unspent)".to_string());
				}
			},
			Err(err) => {
				println!("error = {}", err);
				return Err(err.to_string());
			}
		};
		println!("sc = {}", script_pubkey);

		let sig_hash = transaction.signature_hash(0, &script_pubkey, 0x0 as u32);
		println!("sig_hash  = {}", sig_hash);

		let message = secp256k1::Message::from_slice(&sig_hash.to_vec()).expect("Could Not Get Message From SigHash");

		let ctx = Secp256k1::new();
		let pk0 = ctx.recover_ecdsa(&message, &recoverable_signatures[0][0]).expect("Error Derving Public Key");
		let pk1 = ctx.recover_ecdsa(&message, &recoverable_signatures[0][1]).expect("Error Derving Public Key");
		println!("pk0 = {}", pk0);
		println!("pk1 = {}", pk1);
		let bpk0 = bitcoin::PublicKey::new(pk0);
		let bpk1 = bitcoin::PublicKey::new(pk1);
		if script_pubkey.is_p2sh() {
			println!("p2sh")
			//(bitcoin::util::address::Address::p2sh(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2sh(&bpk1, Network::Bitcoin).script_pubkey())
		} else if script_pubkey.is_p2pkh() {
			println!("p2pkh")
			//(bitcoin::util::address::Address::p2pkh(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2pkh(&bpk1, Network::Bitcoin).script_pubkey())
		} else if script_pubkey.is_p2pk() {
			println!("p2pk")
			//(bitcoin::util::address::Address::p2pk(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2pk(&bpk1, Network::Bitcoin).script_pubkey())
		} else if script_pubkey.is_v0_p2wpkh() {
			println!("p2wpkh");
			let scpk0 = bitcoin::util::address::Address::p2wpkh(&bpk0, Network::Bitcoin).expect("Get Address").script_pubkey();
			let scpk1 = bitcoin::util::address::Address::p2wpkh(&bpk1, Network::Bitcoin).expect("Get Address").script_pubkey();
			println!("scpk0 = {}", scpk0);
			println!("scpk1 = {}", scpk1);
		} else if script_pubkey.is_v0_p2wsh() {
			println!("p2wsh")
			//(bitcoin::util::address::Address::p2wsh(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2wsh(&bpk1, Network::Bitcoin).script_pubkey())
		} else if script_pubkey.is_v1_p2tr() {
			println!("p2tr")
			//(bitcoin::util::address::Address::p2tr(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2tr(&bpk1, Network::Bitcoin).script_pubkey())
		} else {
			//Custom Script
			return Err("Cannot get pub key from custom output script".to_string())
		}

		
		//
		//let scpk1 = bitcoin::util::address::Address::p2wpkh(&bpk1, Network::Bitcoin).expect("Could Not Get Address").script_pubkey();
		//if scpk1 == script_pubkey {
		//	println!("pk1");
		//}

		//let bpk0 = bitcoin::PublicKey::new(pk0);
		//let scpk0 = bitcoin::util::address::Address::p2wpkh(&bpk0, Network::Bitcoin).expect("Could Not Get Address").script_pubkey();
		//if scpk0 == script_pubkey {
		//	println!("pk0");
		//}
	}

	for i in half_finished_inputs {
		println!("Half Finished Input = {}", i);


	}

	if input_type == "10" {
		

			
		//let mut hasher = sha256::Hash::new();
		//let mut hasher = sha256::HashEngine::default();
		//pk0.hash(&mut hasher);
		//println!("pk0h = {}", hasher.finish());
		//let message = Message::from_hashed_data::<sha256::Hash>(&pk0.to_vec());
	}
	//else if &control[2..4] == "10" {
		//Custom Script but half compressed locktime
		
		//println!("hi")
		//loop {
		//	match transaction.verify(Spent) {
		//		Ok(_) => break,
		//		Err(_) => transaction.lock_time += pow16
		//	};
		//}
	//}

	
		

		// let message = secp256k1::Message::from_slice(&sig_hash.to_vec()).expect("Could Not Get Message From SigHash");

		// let ctx = Secp256k1::new();
		// let pk0 = ctx.recover_ecdsa(&message, &recoverable_signatures[0][0]).expect("Error Derving Public Key");
		// let pk1 = ctx.recover_ecdsa(&message, &recoverable_signatures[0][1]).expect("Error Derving Public Key");
		// println!("pk0 = {}", pk0);
		// println!("pk1 = {}", pk1);

		// let bpk1 = bitcoin::PublicKey::new(pk1);
		// //let scpk1 = bitcoin::util::address::Address::p2pkh(&bpk1, Network::Bitcoin).script_pubkey();
		// let scpk1 = bitcoin::util::address::Address::p2wpkh(&bpk1, Network::Bitcoin).expect("Could Not Get Address").script_pubkey();
		// if scpk1 == script_pubkey {
		// 	println!("pk1");
		// }

		// let bpk0 = bitcoin::PublicKey::new(pk0);
		// let scpk0 = bitcoin::util::address::Address::p2wpkh(&bpk0, Network::Bitcoin).expect("Could Not Get Address").script_pubkey();
		// if scpk0 == script_pubkey {
		// 	println!("pk0");
		// }

	
	println!("transaction == trans = {}", transaction == trans);
	if transaction != trans {
		println!("transaction.input == trans.input = {}", transaction.input == trans.input);
		println!("transaction.output == trans.output = {}", transaction.output == trans.output);
		println!("transaction.version == trans.version = {}", transaction.version == trans.version);
		println!("transaction.lock_time == trans.lock_time = {}", transaction.lock_time == trans.lock_time);
		panic!("Could not Compress Transaction");
	}
	Ok("done".to_string())
}

pub fn compress_transaction(tx: &String, rpc: &bitcoincore_rpc::Client) -> Result<String, String> {
	//Declare Result
	let mut compressed_transaction = Vec::new();
	//Transaction from hex to bytes
	let bytes = match Vec::from_hex(&tx) {
		Ok(bytes) => bytes,
		Err(error) => {
			println!("error = {}", error);
			return Err(error.to_string())
		}
	};

	//Deserialize Transaction
	let transaction = match Transaction::deserialize(&bytes) {
		Ok(transaction) => transaction,
		Err(error) => {
			return Err(error.to_string())
		}
	};

	//Get the Current Block height
	let block_height = match rpc.get_block_count() {
		Ok(bh) => bh,
		Err(err) => return Err(err.to_string())
	};
	
	//Match the version with binary "00" means uncompressed
	let version_str = match transaction.version {
		1 => "01",
		2 => "10",
		3 => "11",
		_ => "00"
	};

	// limit = 2^16
	let limit = u32::pow(2, 16);

	let scriptt = &transaction.input[0].script_sig;
	let witnesst = &transaction.input[0].witness;
	let first_input_type = match get_input_type(scriptt, &witnesst) {
		Ok(is) => is,
		Err(err) => return Err(err.to_string())
	};

	//TODO: Cannot use for staticts due to unloaded wallet
	//let coinbase_str = match rpc.get_transaction(&transaction.input[0].previous_output.txid, Some(true)) {
	//	Ok(blob) => {
	//	    blob.info TODO:IS NEW COINS?
	//	},
	//	Err(error) => return Err(error.to_string())
	//};

	let coinbase_str = match transaction.input[0].previous_output.vout {
		4294967295 => "1",
		_ => "0"
	};

	//If the Lock time is zero we can repersent that as a single bit(Otherwise half compress it)
	let lock_time_str = match transaction.lock_time {
		0 => "00",
		_ if (first_input_type != "00") && (coinbase_str == "0") => "11",
		_ => "10",
	};

	//Assemble Control Bit v = version, l = lock_time, c = coinbase (vvllc000)
	let mut control_str = String::new();
	control_str += version_str;
	control_str += lock_time_str;
	//control_str += coinbase_str;
	control_str += "0000";

	//Push control bit
	let control: u8 = u8::from_str_radix(&control_str, 2).unwrap();
	compressed_transaction.push(control);
	println!("Control = {}", control_str);

	//If version was uncompressed Push version
	//TODO make varint
	if version_str == "00" {
		compressed_transaction.extend(u32_to_4_bytes(transaction.version as u32));
		println!("Version = {}", hex::encode(hex::encode(u32_to_4_bytes(transaction.version as u32))));
	}

	//If lock_time was uncompressed Push Lock_Time
	if lock_time_str == "11" {
		let second_lock = (transaction.lock_time % limit) as u16;
		let lock_time = u16_to_2_bytes(second_lock);
		println!("Lock Time S = {}", hex::encode(u16_to_2_bytes(second_lock)));
		compressed_transaction.extend(lock_time);
	} else if lock_time_str == "10" {
		println!("Lock Time = {}", transaction.lock_time);
		compressed_transaction.extend(to_varint(transaction.lock_time as i64));
	}

	//Convert the number of inputs to binary "00" is uncompressed varint
	
	let input_count = match transaction.input.len() {
		1 => "01",
		2 => "10",
		3 => "11",
		_ => "00"
	};
	

	//Compress the Sequence using the top three most popular values and weather or not they are identical and if we have only a few inputs
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
		if input_count != "00" {
			sequence_str = "1000".to_string();
			for i in 0..transaction.input.len() {
				sequence_byte += &sequence_vec[i];
			}
			for _ in 0..4-transaction.input.len() {
				sequence_byte += "00";
			}
		}
	}

	fn get_script_sig(script: &Script) -> Result<Option<Vec<u8>>, String> {
		let mut index = 0;
		for instruction in script.instructions() {
			//Not legacy with more then 2 pushes
			if index > 2 {
				break
			}
			//Get instruction
			let instruct = match instruction {
				Ok(i) => i,
				Err(err) => return Err(err.to_string())
			};
			match instruct {
				Instruction::PushBytes(data) => {
					if index == 0 {
						//convert bytes to signature
						match secp256k1::ecdsa::Signature::from_der_lax(data) {
							Ok(signature) => {
								return Ok(Some(signature.serialize_compact().to_vec()));
							},
							Err(_) => break
						};
					}
				},
				Instruction::Op(_) => {
					//If any op codes other then pushbytes not Legacy
					break
				}
			}
			index += 1;
		}
		return Ok(None)
	}

	
	fn get_input_type(script: &Script, witness: &Witness) -> Result<String, String> {
		if (script.as_bytes().len() == 0) && (witness.len() == 1) || (witness.len() == 2) {
			match secp256k1::ecdsa::Signature::from_der(&witness.to_vec()[0]) {
				Ok(_) => return Ok("10".to_string()),
				Err(_) => {
					match secp256k1::ecdsa::Signature::from_der_lax(&witness.to_vec()[0]) {
						Ok(_) => return Ok("11".to_string()),
						Err(_) => return Ok("00".to_string())
					}
				}
			}
		} else {
			match get_script_sig(script) {
				//Legacy script
				Ok(Some(_)) => return Ok("01".to_string()),
				//Custom Script
				Ok(None) => return Ok("00".to_string()),
				Err(err) => return Err(err.to_string())
			}
		}
	}

	//Get input type
	let script = &transaction.input[0].script_sig;
	let witness = &transaction.input[0].witness;
	let mut input_type_str = match get_input_type(script, &witness) {
		Ok(is) => is,
		Err(err) => return Err(err.to_string())
	};

	//Get input Identicalness
	let mut input_identical = true;
	for i in 0..transaction.input.len() {
		let script = &transaction.input[i].script_sig;
		let witness = &transaction.input[i].witness;
		let ist = match get_input_type(script, &witness) {
			Ok(is) => is,
			Err(err) => return Err(err.to_string())
		};
		if ist != input_type_str {
			input_identical = false;
			break
		}
	}

	//Assemble the input_str input count = c, sequence = s, custom script? = u, identical types = i (ccssssui)
	let mut input_str = String::new();
	input_str += input_count;
	input_str += &sequence_str;
	if input_type_str == "00" {
		input_str += "0";
	} else {
		input_str += "1";
	}
	if input_identical {
		input_str += "1";
	} else {
		input_str += "0";
	}
	
	let input: u8 = u8::from_str_radix(&input_str, 2).unwrap();
	compressed_transaction.push(input);
	println!("Input = {}", to_bits(input));

	//If input count greater than 3 push varint
	if &input_str[0..2] == "00" {
		compressed_transaction.extend(to_varint(transaction.input.len() as i64));
		println!("Input Count = {}", transaction.input.len());
	}

	//If sequnce is unique but identical push as 4 bytes
	//If sequence is not identical but also not unique and the inputs are less then 4 push the compressed sequence bit pairs as a byte
	if sequence_str == "0100" {
		compressed_transaction.extend(u32_to_4_bytes(transaction.input[0].sequence));
		println!("0100 Sequence = {}", hex::encode(u32_to_4_bytes(transaction.input[0].sequence)));
	} else if sequence_str == "1000" {
		compressed_transaction.push(u8::from_str_radix(&sequence_byte, 2).unwrap());
		println!("1000 Sequence = {}", u8::from_str_radix(&sequence_byte, 2).unwrap());
	}

	let mut output_str = String::new();
	//Get output count and compress if less then 4
	output_str += match transaction.output.len() {
		1 => "01",
		2 => "10",
		3 => "11",
		_ => "00"
	};
	//Determan output type and identicalness
	
	let script = &transaction.output[0].script_pubkey;


	fn get_output_type(script: &Script) -> String {
		if script.is_p2sh() {
			return "001".to_string()
		} else if script.is_p2pkh() {
			return "010".to_string()
		} else if script.is_p2pk() {
			return "011".to_string()
		} else if script.is_v0_p2wpkh() {
			return "100".to_string()
		} else if script.is_v0_p2wsh() {
			return "101".to_string()
		} else if script.is_v1_p2tr() {
			return "110".to_string()
		} else {
			//Custom Script
			return "111".to_string()
		}
	}

	//Check if output type is identical
	let mut output_type_identical = true;
	let output_type_str = get_output_type(script);
	for i in 0..transaction.output.len() {
		let script = &transaction.output[i].script_pubkey;
		let ots = get_output_type(script);
		if ots != output_type_str {
			output_type_identical = false;
		}
	}
	
	//If output type is identical then push here as a 3 bit number else 000 as unique
	if output_type_identical {
		output_str += &output_type_str;
	} else {
		output_str += "000";
	}
	//TODO: 3 unused bits
	output_str += "000";
	let output: u8 = u8::from_str_radix(&output_str, 2).unwrap();
	compressed_transaction.push(output);
	println!("Output = {}", output_str);

	//If output count was more then 3 push varint
	if &output_str[0..2] == "00" {
		compressed_transaction.extend(to_varint(transaction.output.len() as i64));
		println!("Output Count = {}", transaction.output.len())
	}

	//TODO: remove, used instead of block finding when txid is not in wallet
	let mut txid_vec = Vec::new();
	
	for i in 0..transaction.input.len() {
		//Hard coded compression when having no wallet loaded
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
		println!("Block Height = {}", hex::encode(height));

		compressed_transaction.extend(index);
		println!("Block Index = {}", hex::encode(index));

		//TODO: remove when not deserlizing
		txid_vec.push(transaction.input[i].previous_output.txid);

		compressed_transaction.extend(to_varint(transaction.input[i].previous_output.vout as i64));
		println!("Vout = {}", transaction.input[i].previous_output.vout);

		if !input_identical {
			let script = &transaction.input[i].script_sig;
			let witness = &transaction.input[i].witness;
			input_type_str = match get_input_type(script, witness) {
				Ok(its) => its,
				Err(err) => return Err(err.to_string())
			};
			if input_type_str != "00" {
				compressed_transaction.push(1);
				println!("Custom Script = {}", 1);
			} else {
				compressed_transaction.push(0);
				println!("Custom Script = {}", 0);
			}
			
		}
		match input_type_str.as_str() {
			"01" => {
				let script = &transaction.input[i].script_sig;
				let compact_signature = match get_script_sig(script) {
					Ok(Some(sig)) => sig,
					Err(err) => return Err(err.to_string()),
					Ok(None) => return Err("Invalid Compression".to_string())
				};
				compressed_transaction.extend(&compact_signature);
				println!("01 Sig = {}", hex::encode(&compact_signature));
			},
			"10" => {
				//Segwit uses witnesses the first witness is always the script_sig
				let signature = match secp256k1::ecdsa::Signature::from_der(&transaction.input[i].witness.to_vec()[0]) {
					Ok(ss) => ss,
					Err(err) => return Err(err.to_string())
				};
				let compact_signature = signature.serialize_compact().to_vec();

				compressed_transaction.extend(&compact_signature);
				println!("10 Sig = {}", hex::encode(&compact_signature));
			},
			"11" => {
				//Segwit uses witnesses the first witness is always the script_sig
				let signature = match secp256k1::ecdsa::Signature::from_der_lax(&transaction.input[i].witness.to_vec()[0]) {
					Ok(ss) => ss,
					Err(err) => return Err(err.to_string())
				};
				let compact_signature = signature.serialize_compact().to_vec();

				compressed_transaction.extend(&compact_signature);
				println!("11 Sig = {}", hex::encode(&compact_signature));
			},
			_ => {
				//Custom Signature
				compressed_transaction.push(transaction.input[i].script_sig.len() as u8);
				println!("Script Length = {}", transaction.input[i].script_sig.len());
				
				compressed_transaction.extend(transaction.input[i].script_sig.to_bytes());
				println!("Script = {}", hex::encode(&transaction.input[i].script_sig.to_bytes()));

				let witnesses = transaction.input[i].witness.to_vec();
				compressed_transaction.push(witnesses.len() as u8);
				println!("Witnesses Length = {}", witnesses.len());

				for x in 0..witnesses.len() {
					let witness = &witnesses[x];

					compressed_transaction.push(witness.len() as u8);
					println!("Witness Length = {}", witness.len());

					compressed_transaction.extend(&witness.to_vec());
					println!("Witness = {}", hex::encode(&witness.to_vec()));
				}
			}
		}
		//If sequence could not be compressed append now
		if sequence_str == "0000" {
			compressed_transaction.extend(u32_to_4_bytes(transaction.input[i].sequence));
			println!("0000 Sequence = {}", hex::encode(u32_to_4_bytes(transaction.input[i].sequence)));
		} 

	}
	
	for i in 0..transaction.output.len() {
		compressed_transaction.extend(to_varint(transaction.output[i].value as i64));
		println!("Amount = {}", transaction.output[i].value);

		let script = &transaction.output[i].script_pubkey;
		let output_type_str = get_output_type(script);
		let scriptb = &script.to_bytes();
		match output_type_str.as_str() {
			"001" => {
				if !output_type_identical {
					//If output type is not identical push before every output
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()-1].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()-1].to_vec()));
			},
			"010" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[3..scriptb.len()-2].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[3..scriptb.len()-2].to_vec()));
			},
			"011" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[1..scriptb.len()-1].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[1..scriptb.len()-1].to_vec()));
			},
			"100" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()].to_vec()));
			},
			"101" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()].to_vec()));
			},
			"110" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()].to_vec()));
			},
			"111" => {
				//Custom Script
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.push(transaction.output[i].script_pubkey.len() as u8);
				println!("Script Length = {}", transaction.output[i].script_pubkey.len());

				compressed_transaction.extend(transaction.output[i].script_pubkey.to_bytes());
				println!("Script = {}", hex::encode(transaction.output[i].script_pubkey.to_bytes()));
			}
			_ => return Err("Unknown error Compressing Output Script".to_string())
		};
	}

	let result = hex::encode(compressed_transaction);
	match deserialize(&result, rpc, transaction, txid_vec) {
		Ok(_) => println!("Success"),
		Err(err) => {
			panic!("err: {}", err.to_string());
		}
	};
	return Ok(result)
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