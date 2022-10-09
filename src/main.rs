extern crate app;
extern crate bitcoincore_rpc;

use app::trellis::stego;
use app::compress::compress_transaction;
use app::error::Error;


#[cfg(feature="gui")]
use app::gui::gui;

use std::fs::File;
use std::process;
use std::io::Read;
use bitcoincore_rpc::{Auth, Client};
use crate::bitcoincore_rpc::RpcApi;


fn pretty_unwrap<T>(msg: &str, res: Result<T, Error>) -> T {
    match res {
        Ok(r) => r,
        Err(error) => {
            print!("{}: ", msg);
            match error {
                Error::CompressingTransactionError => {
                    println!("Could not Compress Transaction: {}", error);
                },
                // Otherwise just print the error
                e => println!("{}", e)
            }
            process::exit(1);
        }
    }
}

pub fn main() {
	

	if cfg!(feature = "gui") {
		#[cfg(feature="gui")]
		pretty_unwrap("Run the GUI", gui());
	} else {
		let mut rpcport = String::new();
		let mut rpcuser = String::new();
		let mut rpcpass = String::new();
		let dot_bitcoin = "/home/a/.bitcoin".to_string();
	    let mut file = File::open(dot_bitcoin+"/bitcoin.conf").expect("can't open bitcoin.conf located {}");
	    let mut contents = String::new();
	    file.read_to_string(&mut contents).expect("unable to read file contents");
	    let lines = contents.split('\n');
	    for line in lines {
	        let property = line.split('=');
	        let property_vec = property.collect::<Vec<&str>>();
	        if property_vec[0] == "rpcuser" {
	            rpcuser = property_vec[1].to_string();
	        } else if property_vec[0] == "rpcpassword" {
	            rpcpass = property_vec[1].to_string();
	        } else if property_vec[0] == "rpcport" {
	            rpcport = property_vec[1].to_string();
	        }
	    }
	    println!("rpcuser = {}",rpcuser);
	    println!("rpcpass = {}", rpcpass);
	    println!("rpcport = {}", rpcport);
	    let rpc = Client::new(
			&("http://localhost:".to_owned()+&rpcport),
	  		Auth::UserPass(
	  			rpcuser,
	            rpcpass
	       	)
	    ).unwrap();
		println!("GUI unenabled");
		//old tr
		//let txr = "02000000000101772251c4eb6c0fabdf689ca9703cdd107c6646b98f69d2fece5ef8e65112e06b0100000000feffffff01007083d05d060000225120ca1e131a2d01740a251d8bd0167bb032999b124c40ea23a1f87b9f5d713f97170140eb49c37a62ad556d55a42e560ef1a651ac32f5705ed06ce5185b63881eda4b269cb82338fb2b72ba7d35eb69659e440a0b4455d9c6cb6e5fd6de78c4ea0dd82cb4790800".to_string();
		//tr
		// let txr = "02000000000101f36f35b933bb1a136a0633585f2a70ab1877716bbcc46b0c04b4651fb134f68b0100000000ffffffff01a861000000000000160014ef28d520689aceb00b7c0264d97e505ece5fa2120140bbc1b94d6ba49f5f2c9c9ed7ef43f264ea60f6f107c2686d23f04d9cdc24608b190d43fc76f30afe4bf43cc45ca26ef109f7404cab5d5c761d874b3d757b355500000000".to_string();
		//p2pkh
		// let txr = "02000000010f7bb3af0aa10954a7fa555f78d058314e5869fa4c774bf4bdde41f153028c42010000006a473044022043145852fcdf1296680d764c161d6e24d1b4e4ad4ca1fd44f8fdd2ae7c8d2ecb022028e41a87ee6b39e38e57e8ee45f029678a8856b5139c78e77ffbbdd4d5f491fa0121038e0bfb625d7ef6182d653a7787f56f161a25c8e974186e9027b72bca8a569f1fffffffff01a861000000000000160014733154bc73b07fa0576b2a29a747753be1d0e8d800000000".to_string();
		let txr = "01000000017afcd3403a2ee93dacdeda9802e42da8bb4e5e95223de3fc1ef2733f540786553f0000008b483045022100e6c21f3771ceb926cdeefa3784a0ddeba44089e731b536a560a7fda21d05bc31022061f8d8bf049966fe6a61ea8cfd0930d4e71229b39b1e48aa59c9471dd2233668014104350214d331d5947e8e9c6d937684385ff8e28d8055374704f26b8bdbd3c44d74ffd6af88865d350011c1255ddcdff416439e3a46b93b3fd463b906ff236beec0ffffffff02e6d50700000000001976a91453dce6052e05d0296ebc4c83bd24d0b108affc7988ac03d80000000000001976a91436bb1b3763fb824a23d84b163c9d0a060a79090388ac00000000".to_string();
		pretty_unwrap("Compressing Transaction", compress_transaction(&txr, &rpc));
		// let bc = rpc.get_block_count().expect("Could Not Get Block Count");
  //       for y in 0..100000 {
  //           let i = bc - y;
  //           println!("B-----------------------------------------------------I = {}", i);
  //           let bh = rpc.get_block_hash(i).expect("Could Not Get Block Hash");
  //           let txs = rpc.get_block_info(&bh).expect("Could Not Get Block Info").tx;
  //           for x in 0..txs.len() {
  //               println!("T-----------------------------------------------B = {} X = {}", i, x);
  //               let tx = txs[x];
  //               println!("tx = {}", tx);
  //               let transaction = rpc.get_raw_transaction_hex(&tx, None).expect("Could Not Find Transaction");
  //               let ctx = pretty_unwrap("Compressing Transaction", compress_transaction(&transaction, &rpc));
  //               println!("tranlen = {}, ctxlen = {}, diff = {}", transaction.len(), ctx.len(), transaction.len()-ctx.len());
  //           }
  //           println!("bc = {}", i);
  //       }
		// let txr = "".to_string();
	}
}

// createrawtransaction '[{"txid":"8bf634b11f65b4040c6bc4bc6b717718ab702a5f5833066a131abb33b9356ff3","vout":1}]' '[{"bc1qau5d2grgnt8tqzmuqfjdjljstm89lgsjuxqgu5": 0.00025}]'