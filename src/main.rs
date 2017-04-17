#![allow(non_camel_case_types)]

use std::io::{self, BufRead, BufReader, Write};
use std::borrow::Borrow;
use std::fs::File;
use std::fmt::Write as FmtWrite;
use std::error::Error;

extern crate sha_1 as sha1;
extern crate md_5 as md5;
extern crate sha2;
extern crate digest;
use digest::Digest;

extern crate rayon;
use rayon::prelude::*;

extern crate permutohedron;
use permutohedron::Heap;

extern crate time;
use time::Timespec;

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

fn slice_join<T: Clone, V: Borrow<[T]>>(slice: &[V], sep: &[T]) -> Vec<T> {
    if slice.len() == 0 {
        return Vec::new();
    }
    let total_len = slice.iter().map(|v| v.borrow().len()).sum::<usize>() + sep.len() * slice.len().saturating_sub(1);
    let mut result = Vec::with_capacity(total_len);
    result.extend_from_slice(slice[0].borrow());
    for v in &slice[1..] {
        result.extend_from_slice(sep);
        result.extend_from_slice(v.borrow());
    }
    result
}

fn hash_data<D: Digest>(mut hash: D, data: &[u8]) -> String {
    hash.input(data);
    let output_bytes = hash.result();
    let mut output_str = String::with_capacity(output_bytes.len() * 2);
    for byte in output_bytes {
        write!(output_str, "{:02x}", byte).unwrap();
    }
    output_str
}

// Generate a hash from the input based on the requested hash type
// Less duplicated code needed here
fn generate_hash(hash: &Hashes, data: &[u8]) -> String {
    match hash {
        &Hashes::md5 => { let hasher = md5::Md5::default(); hash_data(hasher, data) },
        &Hashes::sha1 => { let hasher = sha1::Sha1::default(); hash_data(hasher, data) },
        &Hashes::sha224 => { let hasher = sha2::Sha224::default(); hash_data(hasher, data) },
        &Hashes::sha256 => { let hasher = sha2::Sha256::default(); hash_data(hasher, data) },
        &Hashes::sha384 => { let hasher = sha2::Sha384::default(); hash_data(hasher, data) },
        &Hashes::sha512 => { let hasher = sha2::Sha512::default(); hash_data(hasher, data) },
    }
}

// Read lines from file into a Vec of lines
fn read_file(filename: &str) -> Result<Vec<Vec<u8>>, Box<Error>> {
    let mut f = BufReader::new(File::open(filename)?);

    let mut result = Vec::new();
    let mut buffer = Vec::new();
    loop {
        if f.read_until(b'\n', &mut buffer)? == 0 {
            // EOF
            break;
        }
        // Read until includes the newline if there is one. Remove it.
        if *buffer.last().unwrap() == b'\n' { // unwrap safe because read_until didn't return 0
            buffer.pop();
        }
        result.push(buffer.clone());
        buffer.clear();
    }
    Ok(result)
}

struct Config {
    hash_alg: Hashes,
    delimeter: String,
    filename: String,
    match_hash: String,
    start_end_time: Option<(Timespec, Timespec)>,
}

fn config_from_cli() -> Result<Config, Box<Error>> {
    let matches = App::new(crate_name!())
                          .version(crate_version!())
                          .author(crate_authors!())
                          .about(crate_description!())
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
                                .requires("endtime")
                                .required(false))
                          .arg(Arg::with_name("endtime")
                                .short("e")
                                .long("endtime")
                                .value_name("end_time")
                                .help("Define an end time")
                                .takes_value(true)
                                .requires("starttime"))
                          .get_matches();

    let start_end_time = match (matches.value_of("starttime"), matches.value_of("endtime")) {
        (Some(st), Some(et)) => Some((
            time::strptime(&st, "%Y-%m-%d %H:%M:%S")?.to_timespec(),
            time::strptime(&et, "%Y-%m-%d %H:%M:%S")?.to_timespec()
        )),
        _ => None
    };

    Ok(Config {
        hash_alg: value_t!(matches, "alg", Hashes)?,
        delimeter: value_t!(matches, "delim", String)?,
        filename: value_t!(matches, "file", String)?,
        match_hash: value_t!(matches, "match", String)?,
        start_end_time: start_end_time,
    })
}

fn main() {
    macro_rules! ok_or_exit {
        ($res:expr, $msg:expr) => {
            match $res {
                Ok(val) => val,
                Err(e) => {
                    writeln!(io::stderr(), "ERROR: {}: {}", $msg, e).unwrap();
                    return
                }
            }
        }
    };

    let config = ok_or_exit!(config_from_cli(), "failed to parse command line");
    let delim = config.delimeter.as_bytes();
    let match_hash = config.match_hash;
    let hash_alg = config.hash_alg;
    let file_data = ok_or_exit!(read_file(&config.filename[..]), "failed to read file");
    let mut file_data: Vec<&[u8]> = file_data.iter().map(|line| &line[..]).collect();

    if let Some((st, et)) = config.start_end_time {
        for x in st.sec..et.sec {
            let new_segment = x.to_string().into_bytes();
            let mut segments = file_data.clone();
            segments.push(&new_segment);
            let heap: Vec<Vec<&[u8]>> = Heap::new(&mut segments).collect();

            let r = heap.par_iter().map(|items| slice_join(items, delim)).find_any(|x| generate_hash(&hash_alg, &x) == match_hash);
            if let Some(value) = r {
                println!("[+] Found a matching hash for: {}", String::from_utf8_lossy(&value));
            }
        }
    } else {
        let heap: Vec<Vec<&[u8]>> = Heap::new(&mut file_data).collect();

        let r = heap.par_iter().map(|items| slice_join(items, delim)).find_any(|x| generate_hash(&hash_alg, &x) == match_hash);
        match r {
            Some(value) => 
                println!("[+] Found a matching hash for: {}", String::from_utf8_lossy(&value)),
            None =>
                println!("[+] Search exhausted. Nothing found"),
        }
    }
}
