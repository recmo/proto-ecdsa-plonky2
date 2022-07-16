#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]

use cli_batteries::{run, version};
use ecdsa_plonky2::main as app;

fn main() {
    run(version!(), app);
}
