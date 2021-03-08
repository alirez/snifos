use anyhow::{Context, Result};
use clap::{crate_version, App, Arg};
use snifos::run;

fn main() -> Result<()> {
    let matches = App::new("snifos")
        .version(crate_version!())
        .about("A tool for converting FortiOS sniffer output to pcapng")
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Output file (use - for stdout)")
                .value_name("OUTPUT")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .help("Input file (use - for stdin)")
                .value_name("INPUT")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Enables verbose output"),
        )
        .arg(
            Arg::with_name("split")
                .short("s")
                .long("split")
                .help("Create a new pcapng file for each sniffer run in the input"),
        )
        .arg(
            Arg::with_name("raw")
                .short("r")
                .long("raw")
                .help("Regex matching interfaces converted with the raw link type")
                .value_name("RAW")
                .multiple(true)
                .takes_value(true),
        )
        .get_matches();

    run(&matches).with_context(|| format!("Coversion failed."))
}
