use clap::Clap;
use goblin::error;
use std::fs;

#[derive(Clap, Debug)]
struct Opts {
    input: String,
}

fn main() -> Result<(), error::Error> {
    let opts = Opts::parse();
    let buf = fs::read(opts.input)?;
    let elf = goblin::elf::Elf::parse(&buf)?;
    println!("{:#?}", elf);
    Ok(())
}