#[macro_use]
extern crate lazy_static;

use clap::ArgMatches;
use converter::TextToPcapConverter;
use parser::PacketContext;
use parser::PacketGenerator;
use regex::RegexSet;
use std::{
    fs::{File, OpenOptions},
    io::BufWriter,
};
use thiserror::Error;

pub mod converter;
pub mod parser;

const MAX_FILES: u32 = 20;

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("Parsing failed")]
    ParsingError(#[from] parser::ParsingError),
    #[error("Conversion to pcapng failed")]
    ConverterError(#[from] converter::ConverterError),
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("Regex error")]
    RegexError(#[from] regex::Error),
    #[error("Reached the maximum number of split files ({MAX_FILES})")]
    TooManyFilesError,
    #[error("Unknown error")]
    UnknownError,
}

pub type Result<T> = std::result::Result<T, ConversionError>;

fn create_new_file(file_name: &str) -> std::io::Result<File> {
    eprintln!("Creating a new file: {}", file_name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file_name)
}

fn next_split_file(output_path: &str, file_num: &mut u32) -> Result<String> {
    *file_num += 1;
    if *file_num > MAX_FILES {
        Err(ConversionError::TooManyFilesError)
    } else {
        Ok(format!("{}-{}.pcapng", output_path, file_num))
    }
}

fn make_converter(
    split: bool,
    raw_interfaces: Option<RegexSet>,
    output_path: &str,
    file_num: &mut u32,
) -> Result<TextToPcapConverter<Box<dyn std::io::Write>>> {
    let output_file = get_output_file(split, output_path, file_num)?;
    let converter = TextToPcapConverter::new(output_file, raw_interfaces, output_path == "-");
    Ok(converter)
}

fn get_output_file(
    split: bool,
    output_path: &str,
    file_num: &mut u32,
) -> Result<Box<dyn std::io::Write>> {
    let file_name = if split {
        let next_file = next_split_file(output_path, file_num)?;
        next_file
    } else {
        output_path.to_owned()
    };

    let output_file: Box<dyn std::io::Write> = if output_path == "-" {
        Box::new(std::io::stdout())
    } else {
        match create_new_file(&file_name) {
            Ok(file) => Box::new(BufWriter::new(file)),
            Err(err) => {
                return Err(ConversionError::IoError(err));
            }
        }
    };
    Ok(output_file)
}

pub fn run(matches: &ArgMatches) -> Result<()> {
    let verbose = matches.is_present("verbose");
    let input_path = matches.value_of("input").unwrap();
    let input: Box<dyn std::io::Read> = if input_path == "-" {
        Box::new(std::io::stdin())
    } else {
        match std::fs::File::open(&input_path) {
            Ok(file) => Box::new(file),
            Err(err) => {
                return Err(ConversionError::IoError(err));
            }
        }
    };
    let output_path = matches.value_of("output").unwrap();
    let split = matches.is_present("split");
    let raw = if let Some(r) = matches.values_of("raw") {
        Some(
            RegexSet::new(r.map(|s| s.to_owned()).collect::<Vec<_>>())
                .map_err(|err| ConversionError::RegexError(err))?,
        )
    } else {
        None
    };

    let mut total_packets = 0;
    let mut file_num = 0;
    let mut gen = PacketGenerator::new(input);
    let mut converter: Option<TextToPcapConverter<_>> = None;
    while let Some(item) = gen.next_packet_with_context() {
        match item {
            PacketContext::Parsed(p, ps) => {
                if p.data != &[] {
                    if let None = converter {
                        converter.replace(make_converter(
                            split,
                            raw.clone(),
                            output_path,
                            &mut file_num,
                        )?);
                    }
                    converter
                        .as_mut()
                        .ok_or(ConversionError::UnknownError)?
                        .init_file()?;
                    converter
                        .as_mut()
                        .ok_or(ConversionError::UnknownError)?
                        .handle_packet(&p, ps)?;
                }
            }
            PacketContext::EndOfSet(Some((p, ps))) => {
                if verbose {
                    eprintln!(
                        "Converted {} packet{}",
                        ps.packet_count,
                        if ps.packet_count == 1 { "" } else { "s" }
                    );
                }
                total_packets += ps.packet_count;
                if p.data != &[] {
                    if let None = converter {
                        converter.replace(make_converter(
                            split,
                            raw.clone(),
                            output_path,
                            &mut file_num,
                        )?);
                    }
                    converter
                        .as_mut()
                        .ok_or(ConversionError::UnknownError)?
                        .init_file()?;
                    converter
                        .as_mut()
                        .ok_or(ConversionError::UnknownError)?
                        .handle_packet(&p, ps)?;
                }
                if split {
                    converter.take();
                }
            }
            PacketContext::EndOfSet(None) => {
                if split {
                    converter.take();
                }
            }
        }
    }
    if verbose {
        eprintln!("Total packets converted: {}", total_packets);
    }
    Ok(())
}
