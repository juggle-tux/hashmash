use std::thread;
use std::io::Read;
use std::fs::File;
use std::error::Error;

extern crate crypto;
use crypto::{sha1, sha2, md5};
//use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use crypto::digest::Digest;

extern crate num_cpus;

extern crate scoped_threadpool;
use scoped_threadpool::Pool;

extern crate permutohedron;
use permutohedron::Heap;

#[macro_use]
extern crate clap;
use clap::{Arg, App};

arg_enum!{
    enum Hashes {
        md5,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512
    }
}

arg_enum!{
    #[derive(Debug)]
    enum Delims {
        none,
        colon,
        space,
        ampersand,
        comma,
        period,
        hyphen,
        underscore,
        pipe,
        semicolon
    }
}

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

fn read_file(filename: &str) -> Result<Vec<String>, Box<Error>> {
    let mut buffer = String::new();
    let mut f = try!(File::open(filename));
    try!(f.read_to_string(&mut buffer));

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
                                .default_value("none")
                                .possible_values(&Delims::variants()))
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
                               .get_matches();

    let hash_alg = value_t!(matches.value_of("alg"), Hashes).unwrap();
    let delimeter = value_t!(matches.value_of("delim"), Delims).unwrap();
    let filename = value_t_or_exit!(matches.value_of("file"), String);
    let match_hash = value_t_or_exit!(matches.value_of("match"), String);

    let thread_num = num_cpus::get();

    /*let mut perms = Vec::new();

    let mut pool = Pool::new(thread_num);
    pool.scoped(|scope| {
        // Create references to each element in the vector ...
        for e in &mut vec {
            // ... and add 1 to it in a seperate thread
            scope.execute(move || {
                *e += 1;
            });
        }
    });*/
    println! ("Hash alg is {} {} {} {}", hash_alg, delimeter, filename, match_hash);

    let mut file_data = read_file(&filename[..]).unwrap();

    let mut heap = Heap::new(&mut file_data);
    while let Some(elt) = heap.next_permutation() {
        let res = generate_hash(&hash_alg, &elt.join("-"));
        println!("{:?} {}", elt, res);
        if res == match_hash {
            println! ("Matching {}", &elt.join("-"));
            break;
        }

    }

    /*'outer: for e in &file_data {
        'inner: for f in &file_data {
            let res = generate_hash(&hash_alg, &format!("{}{}", e, f)[..]);
            println!("{}", res);
            if res == match_hash {
                println!("{} {}", e, f);
                break 'outer;
            }
        }
    }*/
}
