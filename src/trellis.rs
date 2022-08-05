use image::io::Reader as ImageReader;
use image::{GenericImageView, Rgb, RgbImage};
use jpeg_encoder::Encoder;
use jpeg_encoder::{ImageBuffer, JpegColorType, rgb_to_ycbcr};



pub struct RgbImageBuffer {
    image: RgbImage,
}

impl ImageBuffer for RgbImageBuffer {
    fn get_jpeg_color_type(&self) -> JpegColorType {
        // Rgb images are encoded as YCbCr in JFIF files
        JpegColorType::Ycbcr
    }

    fn width(&self) -> u16 {
        self.image.width() as u16
    }

    fn height(&self) -> u16 {
        self.image.height() as u16
    }

    fn fill_buffers(&self, y: u16, buffers: &mut [Vec<u8>; 4]){
        for x in 0..self.width() {
            let pixel = self.image.get_pixel(x as u32 ,y as u32);

            let (y,cb,cr) = rgb_to_ycbcr(pixel[0], pixel[1], pixel[2]);

            // For YCbCr the 4th buffer is not used
            buffers[0].push(y);
            buffers[1].push(cb);
            buffers[2].push(cr);
        }
    }
}

pub fn stego(filename: String, _tx: String) -> String {
	
	let mut cover_object: Vec<u64> = Vec::new(); //cover_object vector 
	let mut full_image: Vec<u8> = Vec::new(); // the entire image vector
	let mut cover_weights: Vec<u64> = Vec::new(); //weights for each cover_object bit
	//let jpeg_data = std::fs::read(filename.clone()).expect("failed to read image");

	let img = match ImageReader::open(filename.clone()) { // grab image from filename
		Ok(reader) => match reader.decode() {
			Ok(img) => img,
			Err(e) => panic!("{}", e),
		},
		Err(e) => panic!("{}", e),
	};
	// let img: img::RgbImage = turbojpeg::decompress_image(&jpeg_data).expect("failed to decompress");
	for i in 0..img.height() {
		for ii in 0..img.width() {
			let pixel = img.get_pixel(i, ii); //Get each pixel
			let r = pixel[0]; //grab the red byte
			let mut r_byte = format!("{r:b}"); //convert to binary
			for _ in 0..(8-r_byte.len()) { //pad binary to proper 8 bit form
				let filler: String = String::from("0"); //create 0 string
				r_byte = filler+&r_byte //pad binary
			}
			print!("{}-{}={}, ", i, ii, r);
			for r in r_byte.chars() { //loop through bits in the binary string
				full_image.push(r.to_string().parse::<u64>().unwrap() as u8) // convert to u64 int and push to full image vector
			}
			let r_lsb = r_byte.pop().expect("Never panic").to_string().parse::<u64>().unwrap(); // pop the lsb convert to u64 int
			cover_object.push(r_lsb); //push to cover_object vector
			cover_weights.push(1); //set weight for all bits to 1
			//if cover_object.len() >= 16 {
			//	break 'E
			//}
		}
	}
	println!(";");

	for i in 1..full_image.len() {
		if ((i+1)%8) == 0 {
			assert_eq!(full_image[i], cover_object[(((i+1)/8)-1) as usize] as u8); //assert the full image contains all image bits while the cover object contains only the lsbs
		}
	}
	// let encoder = JpegEncoder::new_with_quality(full_image, 100);
	// img.save("./dog2.png").expect("Faild to save image");
	let mut rgb_image: image::RgbImage = img.to_rgb8();
	
	let i = 0;
	let ii = 0;	

	let pixel = img.get_pixel(i,ii);
	let r = pixel[0];
	let mut r_byte = format!("{r:b}");
	for _ in 0..(8-r_byte.len()) {
		let filler: String = String::from("0");
		r_byte = filler+&r_byte
	}
	r_byte.pop();
	r_byte = r_byte+&"1".to_string();
	// print!("{}-{}={}, ", i, ii, u8::from_str_radix(&r_byte, 2).unwrap());
	let new_pixel = Rgb([u8::from_str_radix(&r_byte, 2).unwrap(), pixel[1], pixel[2]]);
	rgb_image.put_pixel(i, ii, new_pixel);
	let pixel = rgb_image.get_pixel(i, ii); //Get each pixel
	let r = pixel[0]; //grab the red byte
	println!("{}, h", r);
	let mut r_byte = format!("{r:b}"); //convert to binary
	for _ in 0..(8-r_byte.len()) { //pad binary to proper 8 bit form
		let filler: String = String::from("0"); //create 0 string
		r_byte = filler+&r_byte //pad binary
	}
	print!("{}-{}={}, ", i, ii, r);

	println!(";");

	let string = filename;
	let mut encoder = Encoder::new_file(string.clone(), 100).expect("failed to open for write");
	encoder.set_sampling_factor(jpeg_encoder::SamplingFactor::R_4_1_1);
	// encoder.set_progressive_scans(30);
	// print_type_of(&encoder.sampling_factor());
	let image_buffer: RgbImageBuffer = RgbImageBuffer {image: rgb_image};
	encoder.encode_image(image_buffer).expect("Did not encode");

	let img2 = match ImageReader::open(string.clone()) { // grab image from filename
		Ok(reader) => match reader.decode() {
			Ok(img) => img,
			Err(e) => panic!("{}", e),
		},
		Err(e) => panic!("{}", e),
	};
	let mut stego_ob: Vec<u64> = Vec::new();
	for i in 0..img2.height() {
		for ii in 0..img2.width() {
			let pixel = img2.get_pixel(i, ii); //Get each pixel
			let r = pixel[0]; //grab the red byte
			print!("{}-{}={}, ", i, ii, r);
			let mut r_byte = format!("{r:b}"); //convert to binary
			for _ in 0..(8-r_byte.len()) { //pad binary to proper 8 bit form
				let filler: String = String::from("0"); //create 0 string
				r_byte = filler+&r_byte //pad binary
			}
			let r_lsb = r_byte.pop().expect("Never panic").to_string().parse::<u64>().unwrap(); // pop the lsb convert to u64 int
			// println!("test");
			stego_ob.push(r_lsb); //push to cover_object vector
			//if stego_ob.len() >= 16 {
			//	break 'B
			//}
		}
	}
	println!(";");
	print!("cover_object: ");
	for i in 0..cover_object.len() {
		print!("{}, ", cover_object[i]);
	}
	println!(";");
	print!("stego_ob    : ");
	for i in 0..stego_ob.len() {
		print!("{}, ", stego_ob[i]);
	}
	println!(";");
	assert!(cover_object == stego_ob);

	return string;
}