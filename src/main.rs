use iced::button::{self, Button};
use iced::{Alignment, ProgressBar, Column, Theme, Row, Element, Sandbox, Settings, Text, Image, Container, Length};
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
    rpcport: String
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
                let dot_bitcoin = "/home/a/.bitcoin".to_string();
                match compress_transaction(self.text.clone(), dot_bitcoin) {
                    Ok(compressed_transaction) => self.text = compressed_transaction,
                    Err(error) => self.error = error,
                };
                println!("ho");
                if self.error == "" {
                    println!("hi");
                    self.step += 1;
                }
            }
            Message::ClearPressed => {
                self.error = "".to_string();
            }
        }
    }

    fn view(&mut self) -> Element<Message> {
        self.step = 4;
        let dot_bitcoin = "/home/a/.bitcoin";
        let dot_bitcoine = "/home/a/.bitcoin".to_string();
        //match compress_transaction(self.text.clone(), dot_bitcoine) {
        //    Ok(compressed_transaction) => self.text = compressed_transaction,
        //    Err(error) => self.error = error,
        //};
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
              
            } else if self.step == 4 {
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

                let mut row = Row::new()
                    .spacing(10)
                    .push(text_input);

                if valid_transaction(self.text.clone()) {
                    row = row.push(
                        compress_button
                    );
                }

                content = content
                    .padding(20)
                    .align_items(Alignment::Center)
                    .push(
                        Row::new().push(
                            Text::new(
                                format!("Paste in a transaction id")
                            ).size(50)
                        )
                    )
                    .push(row);
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