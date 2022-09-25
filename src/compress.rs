use bitcoin::blockdata::transaction::{Transaction, OutPoint, TxOut, TxIn};
use bitcoin::blockdata::witness::{Witness};
use bitcoin::blockdata::script::Script;
use bitcoin::psbt::serialize::Deserialize;
use bitcoin::{Txid, PackedLockTime, LockTime};

use bitcoin::hashes::Hash;

use bitcoin::network::constants::Network;
use bitcoin::blockdata::script::Instruction;
use secp256k1::Secp256k1;
use bitcoin::hashes::hex::FromHex;
use bitcoin::psbt::Prevouts;
use secp256k1::PublicKey;
use bitcoincore_rpc::RpcApi;

fn u16_to_2_bytes(x:u16) -> [u8;2] {
    let b1 : u8 = ((x >> 8) & 0xff) as u8;
    let b2 : u8 = (x & 0xff) as u8;
    [b1, b2]
}

fn u32_to_4_bytes(x:u32) -> [u8;4] {
    let b1 : u8 = ((x >> 24) & 0xff) as u8;
    let b2 : u8 = ((x >> 16) & 0xff) as u8;
    let b3 : u8 = ((x >> 8) & 0xff) as u8;
    let b4 : u8 = (x & 0xff) as u8;
    [b1, b2, b3, b4]
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
	format!("{:08b}", x)
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
	result
}

fn from_varint(tx: &[u8], oldindex: usize) -> (u64, usize) {
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

		(u64::from_str_radix(&amount_str, 2).unwrap(), index)
}

fn get_script_sig(script: &Script) -> Result<Option<Vec<u8>>, String> {
	for (index, instruction) in script.instructions().enumerate() {
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
	}
	Ok(None)
}

//Declares input compression type:
//00 = Custom Script, Script Hash == No Compression
//01 = Legacy PK Script == Compression using get_script_sig
//01 = Witness only PK Script == Compression using secp256k1::Signature::from_der
//11 = Witness only PK Script == Compression using secp256k1::Signature::from_der_lax
fn get_input_type(script: &Script, witness: &Witness, txin: &TxIn, rpc: &bitcoincore_rpc::Client) -> Result<String, String> {
	if txin.previous_output.vout == 4294967295 {
		//Custom Script(Can't compress a coinbase transaction)
		return Ok("0".to_string())
	};
	let script_pubkey = match rpc.get_tx_out(&txin.previous_output.txid, txin.previous_output.vout, Some(false)) {
		Ok(r) => match r {
			Some(rs) => match rs.script_pub_key.script() {
				Ok(pk) => pk,
				Err(err) => return Err(err.to_string())
			},
			None => return Err("145:Cannot find TX Out(not unspent)".to_string())
		},
		Err(err) => return Err(err.to_string())
	};
	if (script_pubkey.is_p2sh() || script_pubkey.is_v0_p2wsh()) && !script_pubkey.is_p2pkh() && !script_pubkey.is_p2pk() && !script_pubkey.is_v0_p2wpkh() && !script_pubkey.is_v1_p2tr() {
		//Custom Script(Can't compress script hashes)
		return Ok("0".to_string())
	}
	println!("script = {}", hex::encode(&witness.to_vec()[0]));
	println!("wit = {}", witness.to_vec().len());

	match bitcoin::EcdsaSig::from_slice(&witness.to_vec()[0]) {
		Ok(_) => return Ok("1".to_string()),
		Err(_) => {}
	};
	match bitcoin::SchnorrSig::from_slice(&witness.to_vec()[0]) {
		Ok(_) => return Ok("1".to_string()),
		Err(_) => {}
	};
	match get_script_sig(script) {
		//Legacy script
		Ok(Some(_)) => return Ok("1".to_string()),
		//Custom Script
		Ok(None) => return Ok("0".to_string()),
		Err(err) => return Err(err)
	}
	// if script.as_bytes().is_empty() && (witness.len() == 1) || (witness.len() == 2) {
	// 	match secp256k1::ecdsa::Signature::from_der(&witness.to_vec()[0]) {
	// 		Ok(_) => Ok("10".to_string()),
	// 		Err(_) => {
	// 			match secp256k1::ecdsa::Signature::from_der_lax(&witness.to_vec()[0]) {
	// 				Ok(_) => Ok("11".to_string()),
	// 				Err(_) => Ok("00".to_string())
	// 			}
	// 		}
	// 	}
	// } else {
	
}

fn get_witness_script(trans: &Transaction,  rpc: &bitcoincore_rpc::Client, recoverable_signatures: &Vec<&[u8]>, i: usize, mut find_lock_time: bool, outputs: &Vec<TxOut>) -> Result<(Script, Witness, PackedLockTime), String> {
	let mut transaction = trans.clone();
	println!("First Half Finished Input = {}", i);
	let mut result = (transaction.input[i].script_sig.clone(), transaction.input[i].witness.clone(), transaction.lock_time);
	let (script_pubkey, txoutvalue) = match rpc.get_tx_out(&transaction.input[i].previous_output.txid, transaction.input[i].previous_output.vout, Some(false)) {
		Ok(r) => match r {
			Some(rs) => {
				let scpk = match rs.script_pub_key.script() {
					Ok(pk) => pk,
					Err(err) => {
						println!("error = {}", err);
						return Err(err.to_string());
					}
				};
				(scpk, rs.value)
			},
			None => {
				println!("error = Cannot find Tx Out");
				return Err("193: Cannot find TX Out(not unspent)".to_string());
			}
		},
		Err(err) => {
			println!("error = {}", err);
			return Err(err.to_string());
		}
	};
	println!("sc = {}", script_pubkey);

	loop {
		let mut witness = bitcoin::Witness::new();
		if script_pubkey.is_p2sh() {
			println!("p2sh");
			return Err("Cannot get PublicKey From Script Hash Output Script".to_string())
		} else if script_pubkey.is_p2pkh() {
			println!("p2pkh")
			//(bitcoin::util::address::Address::p2pkh(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2pkh(&bpk1, Network::Bitcoin).script_pubkey())
		} else if script_pubkey.is_p2pk() {
			println!("p2pk")
			//(bitcoin::util::address::Address::p2pk(&bpk0, Network::Bitcoin).script_pubkey(), bitcoin::util::address::Address::p2pk(&bpk1, Network::Bitcoin).script_pubkey())
		} else if script_pubkey.is_v0_p2wpkh() {
			let mut recoverable_sigs = Vec::new();
			for x in 0..4 {
				let signature = match secp256k1::ecdsa::RecoverableSignature::from_compact(recoverable_signatures[0], secp256k1::ecdsa::RecoveryId::from_i32(x as i32).expect("Could not create RecoveryId")) {
					Ok(sig) => sig,
					Err(err) => panic!("ERROR: {}", err) 
				};
				recoverable_sigs.push(signature);
			}
			println!("p2wpkh");
			let pkh = bitcoin::PubkeyHash::from_slice(&script_pubkey[2..22]).expect("pubkeyhash fromslice faild");
			let script_code = bitcoin::Script::new_p2pkh(&pkh);
			// LEGACY let sig_hash = transaction.signature_hash(i, &script_pubkey, sig_type as u32);
			let mut shc = bitcoin::util::sighash::SighashCache::new(&transaction);
			let sig_hash = shc.segwit_signature_hash(i, &script_code, txoutvalue.to_sat(), bitcoin::blockdata::transaction::EcdsaSighashType::All).expect("Could not get sighash");
			let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");
			let ctx = Secp256k1::new();
			for rsig in &recoverable_sigs {
				match ctx.recover_ecdsa(&message, &rsig) {
					Ok(e) => println!("e = {}", e),
					Err(e) => println!("ee = {}", e)
				}
			}
			
			let mut public_keys = Vec::new();
			for rsig in &recoverable_sigs {
				if let Ok(pk) = ctx.recover_ecdsa(&message, &rsig) { public_keys.push((rsig,pk)) }
			}
			println!("test = {}", public_keys.len());
		
			for pksig in &public_keys {
				let pubkey = pksig.1;
				let sig = pksig.0.to_standard();
				println!("pk = {}", pubkey);
				//TODO: dose this need to be true for all recoverd pubkeys or will it only work for the correct one? If so why check if pubkeys match at all after?
				//Theory: Will always be true due to the sig being used, If using the original signature it will only work for the true pubkey
				assert!(ctx.verify_ecdsa(&message, &sig, &pubkey).is_ok());
				let bpk = bitcoin::PublicKey::new(pubkey);
				println!("bpk = {}", bpk);
				let scpk = bitcoin::util::address::Address::p2wpkh(&bpk, Network::Bitcoin).expect("Get Address").script_pubkey();
				println!("{} == {} = {}", scpk, script_pubkey, scpk == script_pubkey);
				if scpk == script_pubkey {
					let mut stand_sig = sig.serialize_der().to_vec();
					stand_sig.push(0x01);
					witness.push(&stand_sig);
					witness.push(&bpk.to_bytes());
					result.1 = witness.clone();
					result.2 = transaction.lock_time;
					find_lock_time = false;
					break
				}
			}
		} else if script_pubkey.is_v0_p2wsh() {
			println!("p2wsh");
			return Err("Cannot get PublicKey From Script Hash Output Script".to_string())
		} else if script_pubkey.is_v1_p2tr() {
			println!("p2tr");
			let prevouts = Prevouts::All(&outputs);
			// LEGACY let sig_hash = transaction.signature_hash(i, &script_pubkey, sig_type as u32);
			let mut shc = bitcoin::util::sighash::SighashCache::new(&transaction);
			let sig_hash = shc.taproot_signature_hash(i, &prevouts, None, None, bitcoin::SchnorrSighashType::All).expect("Could not get sighash");
			let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");

			let signature = secp256k1::schnorr::Signature::from_slice(recoverable_signatures[i]).expect("Could not parse signature");
			
			let ctx = Secp256k1::new();
			let pubkey = PublicKey::from_slice(&script_pubkey[2..22]).expect("test");
			let x_only_pubkey = pubkey.x_only_public_key().0;
			assert!(ctx.verify_schnorr(&signature, &message, &x_only_pubkey).is_ok());
			let scpk = bitcoin::util::address::Address::p2tr(&ctx, x_only_pubkey.clone(), None, Network::Bitcoin).script_pubkey();
			println!("{} == {} = {}", scpk, script_pubkey, scpk == script_pubkey);
			if scpk == script_pubkey {
				find_lock_time = false;
			}
		} else {
			//Custom Script
			return Err("Cannot get PublicKey From Custom Output Script".to_string())
		}
		if !find_lock_time {
			break
		} else {
			let pow = u32::pow(2, 16);
			let current_lock_time = transaction.lock_time.to_u32();
			transaction.lock_time = LockTime::from_consensus(current_lock_time+pow).into();
		}
	}
	Ok(result)
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

		let _block_height = u32::from_be_bytes(tx[index..index+4].try_into().expect("slice with incorrect length"));
		println!("Block Height = {}", hex::encode(&tx[index..index+4]));
		index += 4;

		let _block_index = u16::from_be_bytes(tx[index..index+2].try_into().expect("slice with incorrect length")) as usize;
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

		//Get Script and Witness
		let (script, witness) = match input_type_str {
			"1" => {
				//"1" input type is a compressed compact signature
				let script = Script::new();
				let bytes = &tx[index..index+64];
				println!("01 10 11 Sig = {}", hex::encode(&tx[index..index+64]));
				index += 64;
				recoverable_signatures.push(bytes);
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
			true if sequence_vec.is_empty() => global_sequence,
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

		//assemble OutPoint
		let outpoint = OutPoint::new(txid, vout as u32);
		let txin = TxIn {
			previous_output: outpoint,
			script_sig: script,
			sequence: bitcoin::Sequence(sequence),
			witness
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
				println!("Output Script = {}", hex::encode(&tx[index..index+20]));
				index += 20;
				let mut script: Vec<u8> = Vec::new();
				script.push(169);
				script.push(20);
				script.extend(bytes);
				script.push(135);
				match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				}
			},
			"010" => {
				//p2pkh
				let bytes = &tx[index..index+20];
				println!("Output Script = {}", hex::encode(&tx[index..index+20]));
				index += 20;
				let mut script: Vec<u8> = Vec::new();
				script.push(118);
				script.push(169);
				script.push(20);
				script.extend(bytes);
				script.push(136);
				script.push(172);
				match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				}
			},
			"011" => {
				//p2pk
				let bytes = &tx[index..index+65];
				println!("Output Script = {}", hex::encode(&tx[index..index+20]));
				index += 65;
				let mut script: Vec<u8> = Vec::new();
				script.push(65);
				script.extend(bytes);
				script.push(172);
				match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				}
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
				match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				}
			},
			"101" => {
				//v0_p2wsh
				let bytes = &tx[index..index+32];
				println!("Output Script = {}", hex::encode(&tx[index..index+20]));
				index += 32;
				let mut script: Vec<u8> = Vec::new();
				script.push(0);
				script.push(32);
				script.extend(bytes);
				match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				}
			},
			"110" => {
				//p2tr
				let bytes = &tx[index..index+32];
				println!("Output Script = {}", hex::encode(&tx[index..index+20]));
				index += 32;
				let mut script: Vec<u8> = Vec::new();
				script.push(81);
				script.push(32);
				script.extend(bytes);
				match Script::from_hex(&hex::encode(script)) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				}
			},
			"111" => {
				//Custom Script
				let script_length = tx[index] as usize;
				println!("Output Script Length = {}", script_length);
				index += 1;

				let script_pubkey = match Script::from_hex(&hex::encode(&tx[index..index+script_length])) {
					Ok(ss) => ss,
					Err(e) => {
						println!("error = {}", e);
						return Err(e.to_string());
					}
				};
				println!("Output Script = {}", hex::encode(&tx[index..index+script_length]));
				index += script_length;
				script_pubkey
			}
			_ => return Err("Invalid Output Script Compression Byte".to_string())
		};
		
		let tx_out = TxOut {
			value: amount,
			script_pubkey 
		};
		tx_outs.push(tx_out);
	};

	//Assemble Transaction
	let mut transaction = Transaction {
		version,
		lock_time: bitcoin::PackedLockTime(lock_time),
		input: tx_ins.clone(),
		output: tx_outs
	};

	// println!("SCRIPT SIG = {}", trans.input[0].script_sig);
	// println!("Witness.len = {}", trans.input[0].witness.to_vec().len());
	// println!("WITNESS[0] = {}", hex::encode(&trans.input[0].witness.to_vec()[0]));
	// println!("WITNESS[1] = {}", hex::encode(&trans.input[0].witness.to_vec()[1]));

	// let pubkey = &trans.input[0].witness.to_vec()[1];
	// let pkh = bitcoin::hashes::hash160::Hash::hash(pubkey);
	// println!("PUB KEY HASH = {}", pkh);

	
	if &control[2..4] == "11" {
		assert!(!half_finished_inputs.is_empty());
		let (_, _, lock_time) = get_witness_script(&transaction, rpc, &recoverable_signatures, 0, true, &transaction.output)?;
		transaction.lock_time = lock_time;
		//half_finished_inputs.remove(0);
	} 
	for i in half_finished_inputs {
		let (script_sig, witness, _) = get_witness_script(&transaction, rpc, &recoverable_signatures, i, false, &transaction.output)?;
		transaction.input[i].script_sig = script_sig;
		transaction.input[i].witness = witness;
	}
	

	
	println!("transaction == trans = {}", transaction == trans);
	if transaction != trans {
		println!("transaction.input == trans.input = {}", transaction.input == trans.input);
		if transaction.input != trans.input {
			for a in 0..transaction.input.len() {
				println!("transaction.input[{}].previous_output == trans.input[{}].previous_output = {}", a, a, transaction.input[a].previous_output == trans.input[a].previous_output);
				println!("transaction.input[{}].script_sig == trans.input[{}].script_sig = {}", a, a, transaction.input[a].script_sig == trans.input[a].script_sig);
				println!("transaction.input[{}].sequence == trans.input[{}].sequence = {}", a, a, transaction.input[a].sequence == trans.input[a].sequence);
				println!("transaction.input[{}].witness == trans.input[{}].witness = {}", a, a, transaction.input[a].witness == trans.input[a].witness);
				for b in 0..transaction.input[a].witness.to_vec().len() {
					println!("hex::encode(transaction.input[{}].witness.to_vec()[{}]) = {}", a, b, hex::encode(&transaction.input[a].witness.to_vec()[b]));
					println!("hex::encode(trans.input[{}].witness.to_vec()[{}]) = {}", a, b, hex::encode(&trans.input[a].witness.to_vec()[b]));
				}
			}
		}
		println!("transaction.output == trans.output = {}", transaction.output == trans.output);
		println!("transaction.version == trans.version = {}", transaction.version == trans.version);
		println!("transaction.lock_time == trans.lock_time = {}", transaction.lock_time == trans.lock_time);
		panic!("Could not Compress Transaction");
	}
	Ok("done".to_string())
}

pub fn compress_transaction(tx: &str, rpc: &bitcoincore_rpc::Client) -> Result<String, String> {
	//Declare Result
	let mut compressed_transaction = Vec::new();
	//Transaction from hex to bytes
	let bytes = match Vec::from_hex(tx) {
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
			println!("deserialize = {}", error);
			return Err(error.to_string())
		}
	};

	//Get the Current Block height
	let _block_height = match rpc.get_block_count() {
		Ok(bh) => bh,
		Err(err) => {
			println!("get_block_count = {}", err);
			return Err(err.to_string())
		}
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
	// println!("vout = {}", transaction.input[0].previous_output.vout);
	let first_input_type = match get_input_type(scriptt, witnesst, &transaction.input[0], rpc) {
		Ok(is) => is,
		Err(err) => {
			return Err(err)
		}
	};

	//TODO: Cannot use for staticts due to unloaded wallet
	// let coinbase_str = match rpc.get_transaction(&transaction.input[0].previous_output.txid, Some(true)) {
	// 	Ok(blob) => {
	// 	    match blob.details[0].category {
	// 	    	GetTransactionResultDetailCategory::Generate => "1",
	// 	    	_ => "0"
	// 	    }
	// 	},
	// 	Err(error) => return Err(error.to_string())
	// };

	let coinbase_str = match transaction.input[0].previous_output.vout {
		4294967295 => "1",
		_ => "0"
	};

	//If the Lock time is zero we can repersent that as a single bit(Otherwise half compress it)
	let lock_time_str = match transaction.lock_time.to_u32() {
		0 => "00",
		_ if (first_input_type == "1") && (coinbase_str == "0") => "11",
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
		let second_lock = (transaction.lock_time.to_u32() % limit) as u16;
		let lock_time = u16_to_2_bytes(second_lock);
		println!("Lock Time S = {}", hex::encode(u16_to_2_bytes(second_lock)));
		compressed_transaction.extend(lock_time);
	} else if lock_time_str == "10" {
		println!("Lock Time = {}", transaction.lock_time);
		compressed_transaction.extend(to_varint(transaction.lock_time.to_u32() as i64));
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
		let sequence_str_temp = match transaction.input[i].sequence.to_consensus_u32() {
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
	} else if sequence_small && input_count != "00" {
		sequence_str = "1000".to_string();
		for sequence_bits in sequence_vec.iter().take(transaction.input.len()) {
			sequence_byte += sequence_bits;
		}
		for _ in 0..4-transaction.input.len() {
			sequence_byte += "00";
		}
	}



	//Get input type
	let script = &transaction.input[0].script_sig;
	let witness = &transaction.input[0].witness;
	let mut input_type_str = match get_input_type(script, witness, &transaction.input[0], rpc) {
		Ok(is) => is,
		Err(err) => return Err(err)
	};
	println!("input_type_str = {}", input_type_str);

	//Get input Identicalness
	let mut input_identical = true;
	for i in 0..transaction.input.len() {
		let script = &transaction.input[i].script_sig;
		let witness = &transaction.input[i].witness;
		let ist = match get_input_type(script, witness, &transaction.input[i], rpc) {
			Ok(is) => is,
			Err(err) => return Err(err)
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
	input_str += &input_type_str;
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
		compressed_transaction.extend(u32_to_4_bytes(transaction.input[0].sequence.to_consensus_u32()));
		println!("0100 Sequence = {}", hex::encode(u32_to_4_bytes(transaction.input[0].sequence.to_consensus_u32())));
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
			"001".to_string()
		} else if script.is_p2pkh() {
			"010".to_string()
		} else if script.is_p2pk() {
			"011".to_string()
		} else if script.is_v0_p2wpkh() {
			"100".to_string()
		} else if script.is_v0_p2wsh() {
			"101".to_string()
		} else if script.is_v1_p2tr() {
			"110".to_string()
		} else {
			//Custom Script
			"111".to_string()
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
			input_type_str = match get_input_type(script, witness, &transaction.input[i], rpc) {
				Ok(its) => its,
				err => return err
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
					Err(err) => return Err(err),
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
				println!("ss = {}", signature);
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

				for witness in witnesses {

					compressed_transaction.push(witness.len() as u8);
					println!("Witness Length = {}", witness.len());

					compressed_transaction.extend(&witness.to_vec());
					println!("Witness = {}", hex::encode(&witness));
				}
			}
		}
		//If sequence could not be compressed append now
		if sequence_str == "0000" {
			compressed_transaction.extend(u32_to_4_bytes(transaction.input[i].sequence.to_consensus_u32()));
			println!("0000 Sequence = {}", hex::encode(u32_to_4_bytes(transaction.input[i].sequence.to_consensus_u32())));
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
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()-1]));
			},
			"010" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[3..scriptb.len()-2].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[3..scriptb.len()-2]));
			},
			"011" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[1..scriptb.len()-1].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[1..scriptb.len()-1]));
			},
			"100" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()]));
			},
			"101" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()]));
			},
			"110" => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()]));
			},
			"111" => {
				//Custom Script
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type_str, 2).unwrap());
					println!("Output Type = {}", output_type_str);
				}
				compressed_transaction.push(transaction.output[i].script_pubkey.len() as u8);
				println!("Output Script Length = {}", transaction.output[i].script_pubkey.len());

				compressed_transaction.extend(transaction.output[i].script_pubkey.to_bytes());
				println!("Output Script = {}", hex::encode(transaction.output[i].script_pubkey.to_bytes()));
			}
			_ => return Err("Unknown error Compressing Output Script".to_string())
		};
	}

	let result = hex::encode(compressed_transaction);
	match deserialize(&result, rpc, transaction, txid_vec) {
		Ok(_) => println!("Success"),
		Err(err) => {
			panic!("err: {}", err);
		}
	};
	Ok(result)
}

pub fn valid_transaction(tx: String) -> String {

	let bytes = match Vec::from_hex(&tx) {
		Ok(bytes) => bytes,
		Err(error) => {
			return error.to_string()
		}
	};
	match Transaction::deserialize(&bytes) {
		Ok(_) => "".to_string(),
		Err(error) => {
			error.to_string()
		}
	}
} 


// pub fn testscp(tx: &String, rpc: &bitcoincore_rpc::Client) -> Result<String, String> {
// 	//Transaction from hex to bytes
// 	let bytes = Vec::from_hex(&tx).expect("could not turn into bytes");
// 	//Deserialize Transaction
// 	let transaction = Transaction::deserialize(&bytes).expect("Could not deserialize");

// 	println!("sig hex = {}", hex::encode(&transaction.input[0].witness.to_vec()[0]));
// 	// let original_signature = match secp256k1::ecdsa::Signature::from_der_lax(&transaction.input[0].witness.to_vec()[0]).expect("Could not parse signature");

// 	println!("sig = {}", original_signature);

// 	let original_public_key = secp256k1::PublicKey::from_slice(&transaction.input[0].witness.to_vec()[1]).expect("Could not derive pubkey");
// 	println!("original_public_key = {}", original_public_key);

// 	let compact_signature = original_signature.serialize_compact().to_vec();


// 	println!("D----------------------------------");

// 	let (script_pubkey, txoutvalue) = match rpc.get_tx_out(&transaction.input[0].previous_output.txid, transaction.input[0].previous_output.vout, Some(false)) {
// 		Ok(r) => match r {
// 			Some(rs) => {
// 				let scpk = match rs.script_pub_key.script() {
// 					Ok(pk) => pk,
// 					Err(err) => {
// 						println!("error = {}", err);
// 						return Err(err.to_string());
// 					}
// 				};
// 				(scpk, rs.value)
// 			},
// 			None => {
// 				println!("error = {}", "Cannot find Tx Out");
// 				return Ok("Cannot find TX Out(not unspent)".to_string());
// 			}
// 		},
// 		Err(err) => {
// 			println!("error = {}", err);
// 			return Err(err.to_string());
// 		}
// 	};
// 	println!("sc = {}", script_pubkey);
// 	let pkh = bitcoin::PubkeyHash::from_slice(&script_pubkey[2..22]).expect("pubkeyhash fromslice faild");
// 	let p2pkh = bitcoin::Script::new_p2pkh(&pkh);
// 	println!("p2pkh = {}", p2pkh);

// 	let ctx = Secp256k1::new();

// 	let mut hash_type = bitcoin::blockdata::transaction::EcdsaSighashType::All;
// 	let mut shc = bitcoin::util::sighash::SighashCache::new(&transaction);

// 	let sig_hash = shc.segwit_signature_hash(0, &p2pkh, txoutvalue.as_sat(), hash_type).expect("Could not get sighash");
// 	let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");
// 	println!("segwit = {}", ctx.verify_ecdsa(&message, &original_signature, &original_public_key).is_ok());

// 	let taproot_sig_hash = shc.taproot_signature_hash(0, sub)
// 	// let legacy_sig_hash = transaction.signature_hash(0, &script_pubkey, 0x01 as u32);
// 	// let legacy_message = secp256k1::Message::from_slice(&legacy_sig_hash).expect("Could Not Get Message From SigHash");
// 	// println!("legacy = {}", ctx.verify_ecdsa(&legacy_message, &original_signature, &original_public_key).is_ok());

// 	// let l2sig_hash = shc.legacy_signature_hash(0, &script_pubkey, hash_type).expect("Could not get sighash");
// 	// let l2message = secp256k1::Message::from_slice(&l2sig_hash).expect("Could Not Get Message From SigHash");
// 	// println!("l2 = {}", ctx.verify_ecdsa(&l2message, &original_signature, &original_public_key).is_ok());

// 	// let sig_hash = shc.segwit_signature_hash(0, &script_code, txoutvalue.as_sat(), hash_type).expect("Could not get sighash");
// 	// let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");
// 	// println!("segwit = {}", ctx.verify_ecdsa(&message, &original_signature, &original_public_key).is_ok());


// 	// let recovered_signature = match secp256k1::ecdsa::RecoverableSignature::from_compact(&compact_signature, secp256k1::ecdsa::RecoveryId::from_i32(0 as i32).expect("Could not create RecoveryId")) {
// 	// 	Ok(sig) => sig,
// 	// 	Err(err) => panic!("ERROR: {}", err) 
// 	// };
	
// 	// let public_key = match ctx.recover_ecdsa(&message, &recovered_signature) {
// 	// 	Ok(pk) => pk,
// 	// 	Err(_) => panic!("NEVER GET HERE")
// 	// };

	
// 	// let bpk = bitcoin::PublicKey::new(original_public_key);
// 	// let scpk = bitcoin::util::address::Address::p2wpkh(&bpk, Network::Bitcoin).expect("Get Address").script_pubkey();
// 	// println!("{} == {} = {}", scpk, script_pubkey, scpk == script_pubkey);
// 	// if scpk == script_pubkey {
// 	// 	println!("FOUND!!");
// 	// }
// 	// assert!(script_pubkey.is_v0_p2wpkh());
// 	assert!(ctx.verify_ecdsa(&message, &original_signature, &original_public_key).is_ok());

// 	return Ok("Completed".to_string())
// }