use iced::button::{self, Button};
use iced::{Color, Alignment, ProgressBar, Column, Theme, Row, Element, Sandbox, Settings, Text, Image, Container, Length};
use iced::widget::text_input::{self, TextInput};
use native_dialog::FileDialog;
use std::fs::File;
use std::io::Read;


extern crate bitcoincore_rpc;
use bitcoincore_rpc::{Auth, Client, RpcApi};

mod trellis;
use trellis::stego;

mod compress;
use compress::valid_transaction;
use compress::compress_transaction;

#[derive(Default)]
struct App {
    step: i32,
    file: String,
    text: String,
    choose_image_button: button::State,
    decrement_button: button::State,
    next_button: button::State,
    text_state: text_input::State,
    compress_button: button::State,
    clear_button: button::State,
    progress: f32,
    error: String,
    rpcuser: String,
    rpcpass: String,
    rpcport: String,
}

#[derive(Debug, Clone)]
enum Message {
    ChooseImagePressed,
    DecrementPressed,
    NextPressed,
    TextInputChanged(String),
    CompressPressed,
    ClearPressed
}

impl Sandbox for App {
    type Message = Message;

    fn new() -> Self {
        Self::default()
    }

    fn title(&self) -> String {
        String::from("App - Iced")
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::ChooseImagePressed => {
                let opener = FileDialog::new();
                match opener.show_open_single_file() {
                    Ok(file) => {
                        match file {
                            Some(buffer) => {
                                self.file = buffer.to_str().expect("Buffer failed to turn into a string").to_string();
                                println!("{}", self.file);
                            }
                            None => println!("No buffer"),
                        }
                    },
                    Err(e) => println!("ERROR: {e}"),
                }
            }
            Message::DecrementPressed => {
                println!("Stegoing");
                let newfile = stego(self.file.clone(), self.text.clone());
                println!("{}", newfile);
            }
            Message::TextInputChanged(string) => {
                println!("{}", string);
                self.text = string;
            }
            Message::NextPressed => {
                self.step += 1;
            }
            Message::CompressPressed => {
                let rpc = Client::new(&("http://localhost:".to_owned()+&self.rpcport),
                              Auth::UserPass(self.rpcuser.clone(),
                                             self.rpcpass.clone())).unwrap();
                match compress_transaction(self.text.clone(), rpc) {
                    Ok(compressed_transaction) => self.text = compressed_transaction,
                    Err(error) => self.error = error,
                };
                if self.error == "" {
                    //self.step += 1;
                }
            }
            Message::ClearPressed => {
                self.error = "".to_string();
            }
        }
    }

    fn view(&mut self) -> Element<Message> {
        if self.step < 2 {
            self.step = 2;
        }
        //V0_p2wpkh
        //self.text = "020000000001029e5f2a1c4d826a10b8a7b6609623160a9a2b9669c26ad8b4bacd8f6463348f9c0000000000ffffffffe9a46d1a213fdc89543edf15ca26683a93f3c64427d3f888c7a55f1a416244aa0100000000ffffffff0170110100000000001600144f19677da66785147bf073ce1890ec3c561444f30247304402203a0f6959c3358eda76f5f3c6ea846f89e5badf285cc6d3cee2f37b5d9d3fa08c02206b47d98cc8b38d56fd95379addcc863b035a98a1c9b0c7f5e8bb6b097f41630301210204900de1a8891e779b4784ff720681a7426e30fae6dda5e29a31f4a36e481b4f024730440220260bd9ff2945fe24fd9b5c66bac1e4f886773ed523a6893dd437e9b0ff2dd548022045e7078f9bd84121024ef0d254874f11ec9570c394a7d4e4820e9e24b293c62a01210368b9438a094a11920fb0d6f4f45fcffb85df12bc981f0853cb2a34aaad83b64e00000000".to_string();
        //V0_p2wpkh
        //self.text = "0100000000010104a6eb752acb06776c518b1c6c6b03cb8fd0e59bb920d468e8db246fba5ef73e0000000000fdffffff02f55c328900000000160014e84854148f2c2a026357de6ac740c4513a9bcfe900f902950000000016001402721c5bd757c7e8970ab1d8102d60a76ed692d70247304402203a1beb2ff149f51980a13e141850376c25de542ae79860451e9cee26c5ab706302205324d42d318507a9231cb7396b62f3eb1d7afc518883f762246332807cc2942f01210332a7d11e4cc0ce991d4fabe12349a55a79c253c65fe8514b14fc206416871e4500000000".to_string();
        //p2pk and p2pkh
        //self.text = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000".to_string();
        //p2sh
        //self.text = "0100000001047fe7104d14f2e0dd3aed130379b09ef934f36a2647daac99f4ef5e0a54ccc5010000008a473044022027ba50ad96773d521504aa68ea0947438ad4ab976bff1e474f3ddb9bceb010e902200ca0ebde0c1cf7e6f2293fb7931f2b0a7ebff19f7ce59d3b6897ae8e5629e4d101410499e6e0c203d5506f50d445dd508e17bd016c2c1052027ca0caca667d439543e2bd153e09f3e90ab4903571bee8fa6c509a580f8dce287940eb2dd4f35c3ee2a3feffffff0200ca9a3b0000000017a9147a1b6b1dbd9840fcf590e13a8a6e2ce6d55ecb8987a46c9b7b0f0000001976a914a19afab69e541ba77dfe2a12cdd362646ea290e688ace3b50700".to_string();
        //Post TR
        //self.text = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00".to_string();
        //self.text = "0100000000010100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac02483045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb022022dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01232103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ac00000000".to_string();
        //TR
        self.text = "020000000001041ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890000000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890100000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890200000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890300000000ffffffff01007ea60000000000225120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d0141b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b3dc778082fd38a9e06a1139e6eea41a8680c7010141be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed010141466d525b97733d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe5807a1cba03a46bf3a7087e940101418dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf90100000000".to_string();
        let dot_bitcoin = "/home/a/.bitcoin".to_string();
        let mut content = Column::new()
        .spacing(20)
        .padding(20)
        .max_width(600);
        if self.error == "" {
            if self.step == 0 { 
                content = content
                    .push(
                        Row::new().push(
                            Text::new(
                                format!("Get Started")
                            ).size(50)
                        )
                    )
                    .push(
                        Row::new().push(
                            Button::new(&mut self.next_button, Text::new("Next"))
                            .on_press(Message::NextPressed)
                        )
                    );
            } else if self.step == 1 {
                content = content
                    .push(
                        Row::new().push(
                            Text::new(
                                format!("Confirm bitcoin core is running and up to date")
                            ).size(40)
                        )
                    ).push(
                        Row::new().push(
                            Button::new(&mut self.next_button, Text::new("Next"))
                            .on_press(Message::NextPressed)
                        )
                    );
            } else if self.step == 2 {
                self.rpcport = "8332".to_string();
                let mut file = File::open(dot_bitcoin.to_owned()+"/bitcoin.conf").expect("can't open bitcoin.conf located {}");
                let mut contents = String::new();
                file.read_to_string(&mut contents).expect("unable to read file contents");
                let lines = contents.split("\n");
                for line in lines {
                    let property = line.split("=");
                    let property_vec = property.collect::<Vec<&str>>();
                    if property_vec[0] == "rpcuser" {
                        self.rpcuser = property_vec[1].to_string();
                    } else if property_vec[0] == "rpcpassword" {
                        self.rpcpass = property_vec[1].to_string();
                    } else if property_vec[0] == "rpcport" {
                        self.rpcport = property_vec[1].to_string();
                    }
                }
                let rpc = Client::new(&("http://localhost:".to_owned()+&self.rpcport),
                              Auth::UserPass(self.rpcuser.clone(),
                                             self.rpcpass.clone())).unwrap();
                match rpc.get_blockchain_info() {
                    Ok(info) => {
                        println!("{}, va", info.verification_progress);
                        self.progress = info.verification_progress as f32;
                    },
                    Err(msg) => {
                        println!("{}msg", msg);
                        self.error = msg.to_string();
                    }
                };

                content = content.push(
                    Row::new().push(
                        Text::new(
                            format!("Wait for bitcoin core to update")
                        ).size(40)
                    )
                ).push(
                    Row::new().push(
                        ProgressBar::new(0.0..=1.0, self.progress)
                    )
                );
                if self.progress > 0.99 {
                    content = content.push(
                        Row::new().push(
                            Button::new(&mut self.next_button, Text::new("Next"))
                            .on_press(Message::NextPressed)
                        )
                    )
                }
                
            } else if self.step == 3 {
                let text_input = TextInput::new(
                    &mut self.text_state,
                    "txid",
                    &self.text,
                    Message::TextInputChanged,
                );

                let compress_button = Button::new(
                    &mut self.compress_button, 
                    Text::new("Compress Transaction")
                )
                .on_press(Message::CompressPressed);

                let row = Row::new()
                    .spacing(10)
                    .push(text_input);

                content = content
                    .padding(20)
                    .align_items(Alignment::Center)
                    .push(
                        Row::new().push(
                            Text::new(
                                format!("Paste in a transaction id")
                            ).size(50)
                        )
                    ).push(row);

                let valid = valid_transaction(self.text.clone());
                if valid == "" {
                    content = content.push(
                        Row::new().push(
                            compress_button
                        )
                    );
                } else {
                    content = content.push(
                        Row::new().push(
                            Text::new(
                                format!("{}", valid)
                            ).style(Color::from([1.0, 0.0, 0.0]))
                        )
                    )
                }
             } else if self.step == 4 {
                content = content
                    .padding(20)
                    .align_items(Alignment::Center)
                    .push(
                        Row::new().push(
                            Text::new(
                                format!("Choose a cover Image")
                            ).size(50)
                        )
                    )
                    .push(
                        Button::new(&mut self.choose_image_button, Text::new("Open JPEG"))
                            .on_press(Message::ChooseImagePressed)
                    )
                    .push(
                        Container::new(
                            Image::new(self.file.clone())
                                .width(Length::Fill)
                                .height(Length::Fill))
                            .width(Length::Fill)
                            .height(Length::Fill)
                            .center_x()
                            .center_y()
                    );
                if self.file != "" {
                    content = content.push(
                        Button::new(&mut self.next_button, Text::new("Next"))
                            .on_press(Message::NextPressed)
                    );
                }
            } else if self.step == 5 {
                content = content
                    .padding(20)
                    .align_items(Alignment::Center)
                    .push(
                        Row::new().push(
                            Text::new(
                                format!("Stego the image and txid")
                            ).size(50)
                        )
                    )
                    .push(
                        Button::new(&mut self.decrement_button, Text::new("Stego"))
                            .on_press(Message::DecrementPressed)
                    );
                
            } else {
                content = content
                .push(
                    Text::new(
                        format!("Could not find step {}", self.step)
                    ).size(12)
                ).into();
            }
        }
        if self.error != "" {
            content = Column::new()
                .push(
                    Text::new(
                            format!("{}", self.error)
                        ).size(25)
                )
                .push(
                    Row::new().push(
                        Button::new(&mut self.clear_button, Text::new("Try again"))
                        .on_press(Message::ClearPressed)
                    )
                );
        }
        
        return Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
    fn theme(&self) -> Theme {
        Theme::Light
    }
}

pub fn main() -> iced::Result {
    App::run(Settings::default())
}