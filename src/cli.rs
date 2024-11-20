use clap::{self, command, Parser, Subcommand};
use core::str;
use std::path::PathBuf;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
#[allow(dead_code)]
pub enum Command {
    Decode { value: String },
    Info { torrent: PathBuf },
    Peers { torrent: PathBuf },
    Download { torrent: PathBuf }
}