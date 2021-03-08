use crate::parser::{Packet, PacketSet};
use pcapng_writer::blocks::options::{
    BlockOption, OptionEndOfOpt, OptionEpbFlags, OptionIfName, OptionIfTsResol, Options,
};
use pcapng_writer::blocks::{EnhancedPacketBlock, InterfaceDescriptionBlock, SectionHeaderBlock};
use pcapng_writer::enums;
use pcapng_writer::utils::DEFAULT_TSRES;
use pcapng_writer::writer::{Endianness, PcapNgWriter};
use regex::RegexSet;
use std::{collections::HashMap, io::Write};
use thiserror::Error;

lazy_static! {
    static ref EOO: BlockOption = OptionEndOfOpt::new_option();
    static ref TSRESOL: BlockOption = OptionIfTsResol::new_option(DEFAULT_TSRES);
}

#[derive(Error, Debug)]
pub enum ConverterError {
    #[error("PCAPNG block write error")]
    PcapngWriteError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ConverterError>;

pub(crate) struct TextToPcapConverter<W: Write> {
    interface_map: HashMap<String, u32>,
    writer: PcapNgWriter<W>,
    started: bool,
    raw_interfaces: Option<RegexSet>,
    flush_on_packet: bool,
}

impl<W: Write> TextToPcapConverter<W> {
    pub fn new(writer: W, raw_interfaces: Option<RegexSet>, flush_on_packet: bool) -> Self {
        let interfaces = HashMap::new();
        let pcapng_writer = PcapNgWriter::new(Endianness::Little, writer);
        Self {
            interface_map: interfaces,
            writer: pcapng_writer,
            started: false,
            raw_interfaces,
            flush_on_packet,
        }
    }

    fn write_shb(&mut self) -> Result<()> {
        let opts = Options::new();
        let shb = SectionHeaderBlock::new_with_defaults(&opts);
        self.writer
            .write(&shb)
            .map_err(|err| ConverterError::PcapngWriteError(err))
    }

    fn write_idb(&mut self, name: &str) -> Result<()> {
        let mut opts = Options::new();
        let nameopt = OptionIfName::new_option(name);

        let linktype = match &self.raw_interfaces {
            Some(re_set) => {
                if re_set.is_match(&name.to_string()) {
                    enums::LinkType::Raw
                } else {
                    enums::LinkType::Ethernet
                }
            }
            None => enums::LinkType::Ethernet,
        };

        opts.add_option(&TSRESOL);
        opts.add_option(&nameopt);
        opts.add_option(&EOO);
        let idb = InterfaceDescriptionBlock::new(linktype, 0, &opts);
        self.writer
            .write(&idb)
            .map_err(|err| ConverterError::PcapngWriteError(err))
    }

    fn write_epb(&mut self, packet: &Packet, interface_index: u32) -> Result<()> {
        let flags_opt = OptionEpbFlags::new_option(
            packet.direction.into(),
            enums::ReceptionType::Unspecified,
            None, // We don't have the FCS
            0,    // We don't have this information
        );
        let mut epb_options = Options::new();
        epb_options.add_option(&flags_opt);
        epb_options.add_option(&EOO);

        let data = &packet.data;
        let nanos = packet.timestamp.timestamp_nanos();
        let epb = EnhancedPacketBlock::new_with_timestamp(
            interface_index,
            DEFAULT_TSRES,
            nanos as u128,
            data.len() as u32,
            data.len() as u32,
            &data[..],
            &epb_options,
        );
        self.writer
            .write(&epb)
            .map_err(|err| ConverterError::PcapngWriteError(err))?;
        if self.flush_on_packet {
            self.writer
                .get_writer_mut()
                .flush()
                .map_err(|err| ConverterError::PcapngWriteError(err))
        } else {
            Ok(())
        }
    }

    pub fn handle_packet(&mut self, packet: &Packet, ps: &PacketSet) -> Result<()> {
        let interface = packet
            .interface
            .as_ref()
            .or(ps.interface.as_ref())
            .map(|o| &o[..])
            .unwrap_or("unknown");

        match self.interface_map.get(interface) {
            Some(&idx) => self.write_epb(&packet, idx),
            None => {
                let new_idx = self.interface_map.len() as u32;
                self.interface_map.insert(interface.to_string(), new_idx);
                self.write_idb(&interface)?;
                self.write_epb(&packet, new_idx)
            }
        }
    }

    pub fn init_file(&mut self) -> Result<()> {
        if !self.started {
            self.write_shb()?;
            self.started = true;
        }
        Ok(())
    }
}
