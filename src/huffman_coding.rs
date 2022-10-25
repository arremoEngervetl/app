use crate::error::Error;
use std::fs::File;
use std::io::Read;
use image::io::Reader as ImageReader;
use either::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
	pub byte: u8,
	pub encoding: String
}

#[derive(Debug, Clone)]
struct Leaf {
	byte: u8,
	weight: u32
}

impl Leaf {
	fn new() -> Leaf {
		Leaf {
			byte: 0,
			weight: 0
		}
	}
}

#[derive(Debug, Clone)]
struct Node {
	left: Box<Either<Self, Leaf>>,
	right: Box<Either<Self, Leaf>>,
	weight: u32
}


impl Node {
	fn new(left: Either<Node, Leaf>, right: Either<Node, Leaf>) -> Node {
		Node {
			left: Box::new(left.clone()),
			right: Box::new(right.clone()),
			weight: left.either(|l| l.weight, |r| r.weight) + right.either(|l| l.weight, |r| r.weight)
		}
	}
}

pub fn generate_huffman_table(bytes: &Vec<u8>) -> Result<Vec<Entry>, Error> {

	let mut sorted_bytes = bytes.clone();
	sorted_bytes.sort_unstable();

	let mut database: Vec<Either<Node, Leaf>> = Vec::new();
	let mut current_byte = sorted_bytes[0];
	let mut current_count = 0;

	for byte in sorted_bytes {
		if byte == current_byte {
			current_count += 1;
		} else {
			database.push(Right(Leaf {
				byte: current_byte,
				weight: current_count
			}));
			current_byte = byte;
			current_count = 1;
		}
	}

	database.push(Right(Leaf {
		byte: current_byte,
		weight: current_count
	}));

	database.sort_unstable_by_key(|e| e.as_ref().either(|l| l.weight, |r| r.weight));

	loop {
		assert!(database.len() >= 1);
		if database.len() == 1 {
			break
		}
		let first = &database[0];
		let second = &database[1];
		let node = if first.as_ref().either(|l| l.weight, |r| r.weight) >= second.as_ref().either(|l| l.weight, |r| r.weight) {
			Node::new(first.clone(), second.clone())
		} else {
			Node::new(second.clone(), first.clone())
		};
		database.remove(1);
		database.remove(0);
		database.push(Left(node));
		database.sort_unstable_by_key(|e| e.as_ref().either(|l| l.weight, |r| r.weight));
	}
	let tree = database[0].clone();

	fn decode_node(e: Either<Node, Leaf>, current_path: String) -> Vec<Entry> {
		let mut huffman_table = Vec::new();
		if e.is_left() {
			let node = e.unwrap_left();
			huffman_table.extend(decode_node(*node.left, current_path.clone()+"0"));
			huffman_table.extend(decode_node(*node.right, current_path.clone()+"1"));
		} else {
			let leaf = e.unwrap_right();
			huffman_table.push(Entry{
				byte: leaf.byte,
				encoding: current_path
			})
		}
		huffman_table.sort_unstable_by_key(|e| e.encoding.len());
		return huffman_table
	}

	let huffman_table: Vec<Entry> = decode_node(tree, "".to_string());

	Ok(huffman_table)
}

pub fn serilize_huffman_table(huffman_table: &Vec<Entry>, ht_info: u8) -> Result<Vec<u8>, Error> {
	let mut sorted_huffman_table = huffman_table.clone();
	sorted_huffman_table.sort_unstable_by_key(|e| e.encoding.len());
	let mut huffman_symbol_count: Vec<u8> = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec();
	let mut symbols: Vec<u8> = Vec::new();
	for entry in huffman_table {
		huffman_symbol_count[entry.encoding.len()] += 1;
		symbols.push(entry.byte);
	}

	let huffman_length: u16 = 2+2+1+huffman_symbol_count.len() as u16 + symbols.len() as u16;

	let mut result: Vec<u8> = Vec::new();
	result.push(0xff);
	result.push(0xc4);
	result.extend(huffman_length.to_be_bytes());
	result.push(ht_info);
	result.extend(huffman_symbol_count);
	result.extend(symbols);
	Ok(result)
}

pub fn huffman_encode(bytes: &Vec<u8>, huffman_table: &Vec<Entry>) -> Result<(usize, Vec<u8>), Error> {
	let mut encoded = String::new();
	for byte in bytes {
		for entry in huffman_table {
			if &entry.byte == byte {
				encoded += &entry.encoding;
				break
			}
		}
	}
	let length = encoded.len();
	let mut result = Vec::new();
	let mut index = 0;
	loop {
		println!("index = {}, length = {}", index, length);
		if index+8 <= length {
			println!("push");
			let byte_string = &encoded[index..index+8];
			
			result.push(u8::from_str_radix(&byte_string, 2).unwrap())
		}
		index += 8;
		if index+8 > length {
			println!("over fill");
			let mut byte_string = encoded[index..length].to_string();
			for i in byte_string.len()..8 {
				byte_string += "0";
			}
			result.push(u8::from_str_radix(&byte_string, 2).unwrap());
			break
		}
	}
	Ok((length, result))
}


pub fn deserilize_huffman_table(serilized_huffman_table: &Vec<u8>) -> Result<(Vec<Entry>, u8), Error> {
	if serilized_huffman_table[0] != 0xff || serilized_huffman_table[1] != 0xc4 {
		return Err(Error::UnParsableHuffmanTable)
	}
	let ht_info = &serilized_huffman_table[4];
	let symbol_count = &serilized_huffman_table[5..5+16].to_vec();
	let symbols = &serilized_huffman_table[5+16..serilized_huffman_table.len()];
	let mut huffman_table = Vec::new();
	let mut encoding = 0;
	let mut index = 0;
	for i in 0..symbol_count.len() {
		for x in 0..symbol_count[i] {
			let mut int = format!("{:b}", encoding);
			for y in int.len()..i {
				int = "0".to_string()+&int;
			}
			println!("byte = {}, encode = {}", symbols[index], format!("{:b}", encoding));
			huffman_table.push(Entry{
				byte: symbols[index],
				encoding: int
			});
			encoding += 1;
			index += 1;
		}
		if symbol_count[i] > 0 {
			encoding += 1;
			encoding *= 2;
		}
	}
	Ok((huffman_table, *ht_info))
}

pub fn huffman_decode(huffman_table: &Vec<Entry>, data: &Vec<u8>) -> Result<Vec<u8>, Error> {
	Ok([0].to_vec())
}