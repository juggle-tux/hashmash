Rust Hashmash
==============

Thought I would get some Rust practice in an reimplement this

https://github.com/rebootuser/Hashmash

Does exactly the same but in Rust and multithreaded.

Building
--------

    cargo build

Dependencies
------------

* rust-crypto
* clap
* rayon
* permutahedron
* time

Does not need nightly Rust

TODO
----

* Add millisecondtimestamp support
* Option to test for all delimeters
* Probably clean up the Rust code a bit
* Add tests and benchmarks
