#![allow(non_camel_case_types)]

use std::io::Read;
use std::fs::File;
use std::error::Error;

extern crate crypto;
use crypto::{sha1, sha2, md5};
//use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use crypto::digest::Digest;

extern crate rayon;
use rayon::prelude::*;

extern crate permutohedron;
use permutohedron::Heap;

extern crate time;

#[macro_use]
extern crate clap;
use clap::{Arg, App};

arg_enum!{
    #[derive(Clone, Copy)]
    enum Hashes {
        md5,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512
    }
}

// Generate a hash from the input based on the requested hash type
// Less duplicated code needed here
fn generate_hash(hash: &Hashes, data: &str) -> String {
    match hash {
        &Hashes::md5 => { let mut hasher = md5::Md5::new(); hasher.input_str(data); hasher.result_str() },
        &Hashes::sha1 => { let mut hasher = sha1::Sha1::new(); hasher.input_str(data); hasher.result_str() },
        &Hashes::sha224 => { let mut hasher = sha2::Sha224::new(); hasher.input_str(data); hasher.result_str() },
        &Hashes::sha256 => { let mut hasher = sha2::Sha256::new(); hasher.input_str(data); hasher.result_str() },
        &Hashes::sha384 => { let mut hasher = sha2::Sha384::new(); hasher.input_str(data); hasher.result_str() },
        &Hashes::sha512 => { let mut hasher = sha2::Sha512::new(); hasher.input_str(data); hasher.result_str() },
    }
}

// Read lines from file into a Vec<String>
fn read_file(filename: &str) -> Result<Vec<String>, Box<Error>> {
    let mut buffer = String::new();
    let mut f = match File::open(filename) {
        Ok(f) => f,
        Err(why) => panic!("Unable to open file {}: {}", filename, why.description())
    };
    match f.read_to_string(&mut buffer) {
        Ok(x) => x,
        Err(why) => panic!("Unable to read from file: {}", why.description())
    };

    let x = buffer
            .lines()
            .map(ToOwned::to_owned)
            .collect();
    return Ok(x);
}

fn main() {
    let matches = App::new("Hashmash")
                          .version("0.1")
                          .author("Sven S. <sven@unlogic.co.uk>")
                          .about("Mashes the Hashes")
                          .arg(Arg::with_name("alg")
                                .short("a")
                                .long("alg")
                                .value_name("algo")
                                .help("Select hashing algorithm")
                                .takes_value(true)
                                .default_value("md5")
                                .possible_values(&Hashes::variants()))
                          .arg(Arg::with_name("delim")
                                .short("d")
                                .long("delim")
                                .value_name("delim")
                                .help("Select delimter")
                                .takes_value(true)
                                .default_value("")
                                .possible_values(&[":", " ", "&", ",", ".", ".", "-", "_", "|", ";", ""]))
                          .arg(Arg::with_name("match")
                                .short("m")
                                .long("match")
                                .value_name("match")
                                .help("The hash value to match")
                                .takes_value(true)
                                .required(true))
                          .arg(Arg::with_name("file")
                                .short("f")
                                .long("file")
                                .value_name("file")
                                .help("File containing values to hash")
                                .takes_value(true)
                                .required(true))
                          .arg(Arg::with_name("starttime")
                                .short("st")
                                .long("starttime")
                                .value_name("start_time")
                                .help("Define a start time")
                                .takes_value(true)
                                .required(false))
                          .arg(Arg::with_name("endtime")
                                .short("e")
                                .long("endtime")
                                .value_name("end_time")
                                .help("Define an end time")
                                .takes_value(true)
                                .requires("starttime"))
                               .get_matches();

    let hash_alg = value_t!(matches, "alg", Hashes).unwrap();
    let delimeter = value_t_or_exit!(matches, "delim", String);
    let filename = value_t_or_exit!(matches, "file", String);
    let match_hash = value_t_or_exit!(matches, "match", String);

    let delim = &delimeter[..];
    let mut file_data = read_file(&filename[..]).unwrap();

    if let Some(s) = matches.value_of("starttime") {
        let st = time::strptime(&s, "%Y-%m-%d %H:%M:%S").unwrap().to_timespec();
        file_data.push(st.sec.to_string());
    }

    println!("{:?}", file_data);

    let heap: Vec<Vec <String>> = Heap::new(&mut file_data).collect();

    let r = heap.par_iter().find_first(|&x| { generate_hash(&hash_alg, &(x.join(delim))) == match_hash });
    if r.is_some() {
        println!("[+] Found a matching hash for: {}", r.unwrap().join(delim));
    } else {
        println!("[+] Search exhausted. Nothing found");
    }
}
