use std::thread;

extern crate crypto;
use crypto::{sha1, sha2, sha3, md5};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

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


    println! ("Hash alg is {} {} {} {}", hash_alg, delimeter, filename, match_hash);

}
