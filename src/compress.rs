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
use bitcoincore_rpc::RpcApi;
use bitcoin::XOnlyPublicKey;
// use bitcoincore_rpc_json::GetTransactionResultDetailCategory;
use crate::error::Error;

use std::fmt;



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

fn get_script_sig(script: &Script) -> Result<Option<Vec<u8>>, Error> {
	for (index, instruction) in script.instructions().enumerate() {
		//Not legacy with more then 2 pushes
		if index > 2 {
			break
		}
		//Get instruction
		let instruct = instruction?;

		match instruct {
			Instruction::PushBytes(data) => {
				if index == 0 {
					//convert bytes to signature
					match bitcoin::EcdsaSig::from_slice(data) {
						Ok(signature) => {
							//TODO:: use just the array
							return Ok(Some(signature.sig.serialize_compact().to_vec()));
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

#[derive(PartialEq)]
enum InputScriptType {
	Custom,
	Legacy,
	Segwit,
	Taproot
}

impl fmt::Display for InputScriptType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InputScriptType::Custom => f.write_str("Custom Script"),
			InputScriptType::Legacy => f.write_str("Legacy Script"),
            InputScriptType::Segwit => f.write_str("Segwit Script"),
            InputScriptType::Taproot => f.write_str("Taproot Script"),

        }
    }
}

#[derive(PartialEq)]
enum OutputScriptType {
	P2PK,
	P2SH,
	P2PKH,
	P2WPKH,
	P2WSH,
	P2TR,
	Custom
}

impl fmt::Display for OutputScriptType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
        	OutputScriptType::P2PK => f.write_str("011"),
            OutputScriptType::P2SH => f.write_str("001"),
			OutputScriptType::P2PKH => f.write_str("010"),
            OutputScriptType::P2WPKH => f.write_str("100"),
            OutputScriptType::P2WSH => f.write_str("101"),
            OutputScriptType::P2TR => f.write_str("110"),
            OutputScriptType::Custom => f.write_str("111")

        }
    }
}

fn get_output_type(script: &Script) -> OutputScriptType {
	if script.is_p2pk() {
		OutputScriptType::P2PK
	} else if script.is_p2sh() {
		OutputScriptType::P2SH
	} else if script.is_p2pkh() {
		OutputScriptType::P2PKH
	} else if script.is_v0_p2wpkh() {
		OutputScriptType::P2WPKH	
	} else if script.is_v0_p2wsh() {
		OutputScriptType::P2WSH
	} else if script.is_v1_p2tr() {
		OutputScriptType::P2TR
	} else {
		OutputScriptType::Custom
	}
}

//Declares input compression type:
//00 = Custom Script, Script Hash == No Compression
//01 = Legacy PK Script == Compression using get_script_sig
//10 = Witness only PK Script == Compression using secp256k1::Signature::from_der
//11 = Witness only PK Script == Compression using secp256k1::Signature::from_der_lax
fn get_input_type(script: &Script, witness: &Witness, txin: &TxIn, rpc: &bitcoincore_rpc::Client) -> Result<InputScriptType, Error> {
	if txin.previous_output.vout == 4294967295 {
		return Ok(InputScriptType::Custom)
	};
	let script_pubkey = rpc.get_raw_transaction_info(&txin.previous_output.txid, None)?.vout[txin.previous_output.vout as usize].script_pub_key.script()?;
	if (script_pubkey.is_p2sh() || script_pubkey.is_v0_p2wsh()) && !script_pubkey.is_p2pkh() && !script_pubkey.is_p2pk() && !script_pubkey.is_v0_p2wpkh() && !script_pubkey.is_v1_p2tr() {
		return Ok(InputScriptType::Custom)
	}

	if !witness.is_empty() && bitcoin::EcdsaSig::from_slice(&witness.to_vec()[0]).is_ok() {
		return Ok(InputScriptType::Segwit)
	};
	if !witness.is_empty() && bitcoin::SchnorrSig::from_slice(&witness.to_vec()[0]).is_ok() {
		return Ok(InputScriptType::Taproot)
	};
	match get_script_sig(script)? {
		Some(_) => Ok(InputScriptType::Legacy),
		None => Ok(InputScriptType::Custom)
	}
}

fn get_witness_script(transa: &Transaction,  rpc: &bitcoincore_rpc::Client, recoverable_signatures: &[&[u8]], i: usize, mut find_lock_time: bool, trans: &Transaction) -> Result<(Script, Witness, PackedLockTime), Error> {
	let mut transaction = transa.clone();
	println!("First Half Finished Input = {}", i);
	let mut result = (transaction.input[i].script_sig.clone(), transaction.input[i].witness.clone(), transaction.lock_time);
	let script_pubkey = rpc.get_raw_transaction_info(&transaction.input[i].previous_output.txid, None)?.vout[transaction.input[i].previous_output.vout as usize].script_pub_key.script()?;
	let txoutvalue = rpc.get_raw_transaction_info(&transaction.input[i].previous_output.txid, None)?.vout[transaction.input[i].previous_output.vout as usize].value;

	println!("sc = {}", script_pubkey);

	loop {
		let mut witness = bitcoin::Witness::new();
		if script_pubkey.is_p2sh() {
			return Err(Error::UnparsableCompression)
		} else if script_pubkey.is_p2pkh() {
			println!("p2pkh");
			let mut sig_iter = trans.input[i].script_sig.instructions();
			let signature = match sig_iter.next().unwrap()? {
				Instruction::PushBytes(data) => {
					bitcoin::EcdsaSig::from_slice(data)?.sig
				},
				Instruction::Op(_) => {
					return Err(Error::UnparsableCompression)
				}
			};
			let public_key = match sig_iter.next().unwrap()? {
				Instruction::PushBytes(data) => {
					secp256k1::PublicKey::from_slice(data)?
				},
				Instruction::Op(_) => {
					return Err(Error::UnparsableCompression)
				}
			};
			println!("signature = {}", signature);
			println!("compact = {}", hex::encode(signature.serialize_compact().to_vec()));
			println!("public_key = {}", public_key);
			println!("recoverable_signatures[{}] = {}", i, hex::encode(recoverable_signatures[i]));

			let mut recoverable_sigs = Vec::new();
			for x in 0..4 {
				let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(recoverable_signatures[i], secp256k1::ecdsa::RecoveryId::from_i32(x as i32)?)?;
				recoverable_sigs.push(signature);
			}
			println!("Recovered Signatures = {}", recoverable_sigs.len());
			let shc = bitcoin::util::sighash::SighashCache::new(&transaction);
			let sig_hash = shc.legacy_signature_hash(i, &script_pubkey, 0x01)?;
			let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");
			println!("message = {}", message);
			let ctx = Secp256k1::new();
			assert!(ctx.verify_ecdsa(&message, &signature, &public_key).is_ok());
			let mut public_keys = Vec::new();
			for rsig in &recoverable_sigs {
				if let Ok(pk) = ctx.recover_ecdsa(&message, rsig) { public_keys.push((rsig,pk)) }
			}
			println!("Derived Pub Keys = {}", public_keys.len());
			for pksig in &public_keys {
				let pubkey = pksig.1;
				let sig = pksig.0.to_standard();
				println!("pk = {}", pubkey);
				println!("pk == pubkey = {}", pubkey == public_key);
				//TODO: dose this need to be true for all recoverd pubkeys or will it only work for the correct one? If so why check if pubkeys match at all after?
				//Theory: Will always be true due to the sig being used, If using the original signature it will only work for the true pubkey
				assert!(ctx.verify_ecdsa(&message, &sig, &pubkey).is_ok());
				let bpk = bitcoin::PublicKey::new(public_key);
				println!("bpk = {}", bpk);
				let scpk1 = bitcoin::util::address::Address::p2pkh(&bpk, Network::Bitcoin).script_pubkey();
				println!("bpkh = {}", bpk.pubkey_hash());
				let scpk = Script::new_p2pkh(&bpk.pubkey_hash());
				println!("scpk1 = {}", scpk1);
				println!("scpk = {}", scpk);
				println!("{} == {} = {}", scpk, script_pubkey, scpk == script_pubkey);
				if scpk == script_pubkey {
					let mut script_sig_vec: Vec<u8> = Vec::new();
					let mut signature = sig.serialize_der().to_vec();
					signature.push(0x01);
					println!("script sig = {}", hex::encode(&signature));
					let signature_length = signature.len();
					let pubkey_length = bpk.to_bytes().len();
					script_sig_vec.push(signature_length as u8);
					script_sig_vec.extend(signature);
					script_sig_vec.push(pubkey_length as u8);
					script_sig_vec.extend(bpk.to_bytes());
					let script_sig: Script = script_sig_vec.try_into()?;
					result.0 = script_sig;
					result.2 = transaction.lock_time;
					find_lock_time = false;
					break
				}
			}
			
		} else if script_pubkey.is_p2pk() {
			println!("p2pk");
		} else if script_pubkey.is_v0_p2wpkh() {
			let mut recoverable_sigs = Vec::new();
			for x in 0..4 {
				let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(recoverable_signatures[0], secp256k1::ecdsa::RecoveryId::from_i32(x as i32)?)?;
				recoverable_sigs.push(signature);
			}
			println!("p2wpkh");
			let pkh = bitcoin::PubkeyHash::from_slice(&script_pubkey[2..22]).expect("pubkeyhash fromslice faild");
			let script_code = bitcoin::Script::new_p2pkh(&pkh);
			let mut shc = bitcoin::util::sighash::SighashCache::new(&transaction);
			let sig_hash = shc.segwit_signature_hash(i, &script_code, txoutvalue.to_sat(), bitcoin::blockdata::transaction::EcdsaSighashType::All)?;
			let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");
			let ctx = Secp256k1::new();
			let mut public_keys = Vec::new();
			for rsig in &recoverable_sigs {
				if let Ok(pk) = ctx.recover_ecdsa(&message, rsig) { public_keys.push((rsig,pk)) }
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
				// let scpk = bitcoin::util::address::Address::p2wpkh(&bpk, Network::Bitcoin).expect("Get Address").script_pubkey();
				let scpk = Script::new_v0_p2wpkh(&bpk.wpubkey_hash().unwrap());
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
			return Err(Error::UnparsableCompression)
		} else if script_pubkey.is_v1_p2tr() {
			println!("p2tr");
			let schnorr_sig = bitcoin::SchnorrSig::from_slice(recoverable_signatures[i])?;
			let signature = schnorr_sig.sig;
			if find_lock_time {
				let sig_hash_type = schnorr_sig.hash_ty;
				assert_eq!(sig_hash_type, bitcoin::SchnorrSighashType::Default);
				let mut outputs = Vec::new();
				for tx_in in &transaction.input {
					let tx_out = &rpc.get_raw_transaction_info(&tx_in.previous_output.txid, None)?.vout[tx_in.previous_output.vout as usize];
					outputs.push(TxOut {
						value: tx_out.value.to_sat(),
						script_pubkey: tx_out.script_pub_key.script()?
					});
				}
				let prevouts = Prevouts::All(&outputs);
				let mut shc = bitcoin::util::sighash::SighashCache::new(&transaction);
				let sig_hash = shc.taproot_key_spend_signature_hash(i, &prevouts, sig_hash_type).expect("Could not get sighash");
				let message = secp256k1::Message::from_slice(&sig_hash).expect("Could Not Get Message From SigHash");
				let x_only_pubkey = XOnlyPublicKey::from_slice(&script_pubkey[2..])?;
				println!("signature = {}", signature);
				println!("message = {}", message);
				println!("Pubkey = {}", x_only_pubkey);
				let ctx = Secp256k1::new();
				if ctx.verify_schnorr(&signature, &message, &x_only_pubkey).is_ok() {
					find_lock_time = false;
				}
			} else {
				witness.push(&signature.as_ref());
				result.1 = witness.clone();
			}
			
		} else {
			//Custom Script
			return Err(Error::UnparsableCompression)
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


fn deserialize(tx_hex: &String, rpc: &bitcoincore_rpc::Client, trans: Transaction) -> Result<String, Error> {
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
			let (version, smindex) = from_varint(&tx, index);
			index += smindex;
			version as i32
		},
		_ => return Err(Error::UnparsableCompression)
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
		_ => return Err(Error::UnparsableCompression)
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
		_ => return Err(Error::UnparsableCompression)
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
			_ => return Err(Error::UnparsableCompression)
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
				_ => return Err(Error::UnparsableCompression)
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
		_ => return Err(Error::UnparsableCompression)
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
		let txid = match &control[4..5] {
			"0" => {
				let (block_height, smindex) = from_varint(&tx, index);
				println!("Block Height = {}", block_height);
				index += smindex;

				let (block_index, smindex) = from_varint(&tx, index);
				println!("Block Index = {}", block_index);
				index += smindex;

				let block_hash = rpc.get_block_hash(block_height as u64)?;

				let block_data = rpc.get_block(&block_hash)?;

				block_data.txdata[block_index as usize].txid()
			},
			"1" =>	{
				use std::str::FromStr;
				let txid = hex::encode(&tx[index..index+32]);
				index += 32;
				Txid::from_str(&txid)?
			},
			_ => return Err(Error::UnparsableCompression)
		};
		

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

				let script = Script::from_hex(&hex::encode(&tx[index..index+script_length]))?;
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
				Script::from_hex(&hex::encode(script))?
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
				Script::from_hex(&hex::encode(script))?
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
				Script::from_hex(&hex::encode(script))?
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
				Script::from_hex(&hex::encode(script))?
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
				Script::from_hex(&hex::encode(script))?
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
				Script::from_hex(&hex::encode(script))?
			},
			"111" => {
				//Custom Script
				let script_length = tx[index] as usize;
				println!("Output Script Length = {}", script_length);
				index += 1;

				let script_pubkey = Script::from_hex(&hex::encode(&tx[index..index+script_length]))?;
				println!("Output Script = {}", hex::encode(&tx[index..index+script_length]));
				index += script_length;
				script_pubkey
			}
			_ => return Err(Error::UnparsableCompression)
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
	}

	if &control[2..4] == "11" {
		assert!(!half_finished_inputs.is_empty());
		let (_, _, lock_time) = get_witness_script(&transaction, rpc, &recoverable_signatures, 0, true, &trans)?;
		transaction.lock_time = lock_time;
		//half_finished_inputs.remove(0);
	} 
	for i in half_finished_inputs {
		println!("-------------------------{}", i);
		let (script_sig, witness, _) = get_witness_script(&transaction, rpc, &recoverable_signatures, i, false, &trans)?;
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

pub fn compress_transaction(tx: &str, rpc: &bitcoincore_rpc::Client) -> Result<String, Error> {
	//Declare Result
	let mut compressed_transaction = Vec::new();
	//Transaction from hex to bytes
	let bytes = Vec::from_hex(tx)?;

	//Deserialize Transaction
	let transaction = Transaction::deserialize(&bytes)?;

	//Get the Current Block height
	// let block_height = rpc.get_block_count()?;
	
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
	let first_input_type = get_input_type(scriptt, witnesst, &transaction.input[0], rpc)?;

	

	let coinbase_str = match transaction.input[0].previous_output.vout {
		4294967295 => "1",
		_ => "0"
	};
	println!("coinbase_str = {}", coinbase_str);

	//If the Lock time is zero we can repersent that as a single bit(Otherwise half compress it)
	let lock_time_str = match transaction.lock_time.to_u32() {
		0 => "00",
		_ if (first_input_type != InputScriptType::Custom) && (coinbase_str == "0") => "11",
		_ => "10",
	};
	println!("lock_time_str = {}", lock_time_str);

	//Assemble Control Bit v = version, l = lock_time, c = coinbase (vvllc000)
	let mut control_str = String::new();
	control_str += version_str;
	control_str += lock_time_str;
	control_str += coinbase_str;
	control_str += "000";

	//Push control bit
	let control: u8 = u8::from_str_radix(&control_str, 2).unwrap();
	compressed_transaction.push(control);
	println!("Control = {}", control_str);

	//If version was uncompressed Push version
	//TODO make varint
	if version_str == "00" {
		compressed_transaction.extend(to_varint(transaction.version as i64));
		println!("Version = {}", transaction.version);
	}

	//If lock_time was uncompressed Push Lock_Time
	if lock_time_str == "11" {
		let second_lock = (transaction.lock_time.to_u32() % limit) as u16;
		let lock_time = second_lock.to_be_bytes();
		println!("Lock Time S = {}", hex::encode(second_lock.to_be_bytes()));
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
	let mut input_type = get_input_type(script, witness, &transaction.input[0], rpc)?;
	println!("input_type = {}", input_type);

	//Get input Identicalness
	let mut input_identical = true;
	for i in 0..transaction.input.len() {
		let script = &transaction.input[i].script_sig;
		let witness = &transaction.input[i].witness;
		let it = get_input_type(script, witness, &transaction.input[i], rpc)?;
		if it != input_type {
			input_identical = false;
			break
		}
	}

	//Assemble the input_str input count = c, sequence = s, custom script? = u, identical types = i (ccssssui)
	let mut input_str = String::new();
	input_str += input_count;
	input_str += &sequence_str;
	if input_type != InputScriptType::Custom {
		input_str += "1";
	} else {
		input_str += "0";
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
		compressed_transaction.extend((transaction.input[0].sequence.to_consensus_u32()).to_be_bytes());
		println!("0100 Sequence = {}", hex::encode((transaction.input[0].sequence.to_consensus_u32()).to_be_bytes()));
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

	//Check if output type is identical
	let mut output_type_identical = true;
	let output_type = get_output_type(script);
	for i in 0..transaction.output.len() {
		let script = &transaction.output[i].script_pubkey;
		let ots = get_output_type(script);
		if ots != output_type {
			output_type_identical = false;
		}
	}
	
	//If output type is identical then push here as a 3 bit number else 000 as unique
	if output_type_identical {
		output_str += &output_type.to_string();
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

	
	for i in 0..transaction.input.len() {
		if coinbase_str == "0" {
			let raw_tx_info = rpc.get_raw_transaction_info(&transaction.input[i].previous_output.txid, None)?;
			let block_hash = raw_tx_info.blockhash.unwrap();
			let block_info = rpc.get_block_info(&block_hash)?;
			let height = block_info.height;
			let index = block_info.tx.iter().position(|&r| r == transaction.input[i].previous_output.txid).unwrap();
			
			compressed_transaction.extend(to_varint(height as i64));
			println!("Block Height = {}", height);

			compressed_transaction.extend(to_varint(index as i64));
			println!("Block Index = {}", index);
		} else {
			compressed_transaction.extend(&transaction.input[i].previous_output.txid.to_vec());
			println!("Txid = {}", transaction.input[i].previous_output.txid);
		}

		compressed_transaction.extend(to_varint(transaction.input[i].previous_output.vout as i64));
		println!("Vout = {}", transaction.input[i].previous_output.vout);
		
		if !input_identical {
			let script = &transaction.input[i].script_sig;
			let witness = &transaction.input[i].witness;
			input_type = get_input_type(script, witness, &transaction.input[i], rpc)?;
			if input_type != InputScriptType::Custom {
				compressed_transaction.push(1);
				println!("Custom Script = {}", 1);
			} else {
				compressed_transaction.push(0);
				println!("Custom Script = {}", 0);
			}
			
		}
		match input_type {
			InputScriptType::Legacy => {
				let script = &transaction.input[i].script_sig;
				println!("script = {}", script);
				let compact_signature = match get_script_sig(script)? {
					Some(sig) => sig,
					None => return Err(Error::UnparsableCompression)
				};
				compressed_transaction.extend(&compact_signature);
				println!("01 Sig = {}", hex::encode(&compact_signature));
			},
			InputScriptType::Segwit => {
				println!("ORIGINAL PUBLIC KEY = {}", hex::encode(&transaction.input[i].witness.to_vec()[1]));
				//Segwit uses witnesses the first witness is always the script_sig
				let signature = bitcoin::EcdsaSig::from_slice(&transaction.input[i].witness.to_vec()[0])?.sig;
				let compact_signature = signature.serialize_compact().to_vec();

				compressed_transaction.extend(&compact_signature);
				println!("10 Sig = {}", hex::encode(&compact_signature));
				
			},
			InputScriptType::Taproot => {
				//schnorr(tr) uses witnesses the first witness is always the script_sig
				//TODO: deserizle and reserlize after confirming sighash type is all, fail if otherwise
				let compact_signature = &transaction.input[i].witness.to_vec()[0];

				compressed_transaction.extend(compact_signature);
				println!("11 Sig = {}", hex::encode(compact_signature));
			},
			InputScriptType::Custom => {
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
			compressed_transaction.extend(transaction.input[i].sequence.to_consensus_u32().to_be_bytes());
			println!("0000 Sequence = {}", hex::encode(transaction.input[i].sequence.to_consensus_u32().to_be_bytes()));
		} 

	}
	
	for i in 0..transaction.output.len() {
		compressed_transaction.extend(to_varint(transaction.output[i].value as i64));
		println!("Amount = {}", transaction.output[i].value);

		let script = &transaction.output[i].script_pubkey;
		let output_type = get_output_type(script);
		let scriptb = &script.to_bytes();
		match output_type {
			OutputScriptType::P2SH => {
				if !output_type_identical {
					//If output type is not identical push before every output
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()-1].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()-1]));
			},
			OutputScriptType::P2PKH => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.extend(scriptb[3..scriptb.len()-2].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[3..scriptb.len()-2]));
			},
			OutputScriptType::P2PK => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.extend(scriptb[1..scriptb.len()-1].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[1..scriptb.len()-1]));
			},
			OutputScriptType::P2WPKH => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()]));
			},
			OutputScriptType::P2WSH => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()]));
			},
			OutputScriptType::P2TR => {
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.extend(scriptb[2..scriptb.len()].to_vec());
				println!("Output Script = {}", hex::encode(&scriptb[2..scriptb.len()]));
			},
			OutputScriptType::Custom => {
				//Custom Script
				if !output_type_identical {
					compressed_transaction.push(u8::from_str_radix(&output_type.to_string(), 2).unwrap());
					println!("Output Type = {}", output_type);
				}
				compressed_transaction.push(transaction.output[i].script_pubkey.len() as u8);
				println!("Output Script Length = {}", transaction.output[i].script_pubkey.len());

				compressed_transaction.extend(transaction.output[i].script_pubkey.to_bytes());
				println!("Output Script = {}", hex::encode(transaction.output[i].script_pubkey.to_bytes()));
			}
		};
	}

	let result = hex::encode(compressed_transaction);
	deserialize(&result, rpc, transaction)?;
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