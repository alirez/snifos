use chrono::{Duration, NaiveDateTime, Utc};
use pcapng_writer::enums;
use regex::{Captures, Regex};
use std::io::{BufRead, BufReader, Read};
use std::str::FromStr;
use thiserror::Error;

const BUFFER_SIZE: usize = 20_000;
const MAX_SUMMARY_LINES: u8 = 3;

lazy_static! {
    static ref FILTER_RE: Regex = Regex::new(r#"^filters=\[(?P<filter>.*?)\]$"#).unwrap();
    static ref INTERFACE_RE: Regex =
        Regex::new(r#"^interfaces=\[(?P<interface_name>.*?)\]$"#).unwrap();
    static ref PACKET_RE: Regex = Regex::new(
        r#"^(?P<offset>0x[0-9a-f]{4})(  |    |\t)(?P<hex>(?: [0-9a-f]{2,4}){1,8})\s*(?P<ascii>.{1,16})$"#
    )
    .unwrap();
    static ref PACKET_SUMMARY_RE: Regex = Regex::new(
        r#"^(?P<timestamp>(?P<abs_time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)|(?P<rel_time>\d+\.\d+)) (?P<interface>[^ ]+) (?P<direction>[^ ]+) (?P<text>.+)$"#
    )
    .unwrap();
    static ref RX_COUNT_RE: Regex = Regex::new(r#"^(?P<count>\d+) packets received by filter$"#).unwrap();
    static ref DROP_COUNT_RE: Regex = Regex::new(r#"^(?P<count>\d+) packets dropped by kernel"#).unwrap();
}

#[derive(Error, Debug)]
pub enum ParsingError {
    #[error("Unknown parsing error, while processing line #{0}")]
    UnknownError(u32),
    #[error("Unexpected input, while processing line #{0}")]
    UnexpectedInput(u32),
    #[error("Unexpected parser state, while processing line #{0}")]
    UnexpectedState(u32),
}

pub type Result<T> = std::result::Result<T, ParsingError>;

#[derive(Debug, Clone, Copy)]
pub enum PacketDirection {
    In,
    Out,
    Unknown,
}

impl FromStr for PacketDirection {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "in" => Ok(PacketDirection::In),
            "out" => Ok(PacketDirection::Out),
            _ => Ok(PacketDirection::Unknown),
        }
    }
}

impl From<PacketDirection> for enums::PacketDirection {
    fn from(dir: PacketDirection) -> Self {
        match dir {
            PacketDirection::In => enums::PacketDirection::Inbound,
            PacketDirection::Out => enums::PacketDirection::Outbound,
            PacketDirection::Unknown => enums::PacketDirection::Unavailable,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum State {
    Out,
    InSnifferHeader,
    InPacketSummary,
    InPacketBytes,
    InSnifferEnding,
}

#[derive(Debug)]
pub struct Packet {
    pub interface: Option<String>,
    pub direction: PacketDirection,
    pub timestamp: NaiveDateTime,
    pub summary: String,
    pub data: Vec<u8>,
    pub ps_index: usize,
    summary_lines: u8,
}

impl Packet {
    fn new(
        interface: Option<String>,
        direction: PacketDirection,
        timestamp: NaiveDateTime,
        summary: String,
        data: Vec<u8>,
        ps_index: usize,
    ) -> Self {
        Packet {
            interface,
            direction,
            timestamp,
            summary,
            data,
            ps_index,
            summary_lines: 0,
        }
    }
}

#[derive(Debug)]
pub struct PacketSet {
    pub start_time: NaiveDateTime,
    pub interface: Option<String>,
    pub filter: Option<String>,
    pub rx_count: Option<u64>,
    pub drop_count: Option<u64>,
    pub packet_count: u64,
}

impl Default for PacketSet {
    fn default() -> Self {
        Self {
            start_time: Utc::now().naive_utc(),
            interface: None,
            filter: None,
            rx_count: None,
            drop_count: None,
            packet_count: 0,
        }
    }
}

#[derive(Debug)]
struct Parser {
    state: State,
    current_packet: Option<Packet>,
    parsed_packet: Option<Packet>,
    packet_sets: Vec<PacketSet>,
    current_line: u32,
    current_set: Option<usize>,
}

impl Parser {
    pub(crate) fn new() -> Self {
        Self {
            state: State::Out,
            current_packet: None,
            parsed_packet: None,
            packet_sets: vec![],
            current_line: 0,
            current_set: None,
        }
    }

    fn packet_set(&self, ps_index: usize) -> Option<&PacketSet> {
        self.packet_sets.get(ps_index)
    }

    fn packet_set_mut(&mut self, ps_index: usize) -> Option<&mut PacketSet> {
        self.packet_sets.get_mut(ps_index)
    }

    fn cur_packet_set_mut(&mut self) -> Option<&mut PacketSet> {
        self.packet_set_mut(self.current_set?)
    }

    fn extract_interface(&mut self, caps: Captures) -> Result<()> {
        let cl = self.current_line;
        let packet_set = self
            .cur_packet_set_mut()
            .ok_or(ParsingError::UnexpectedState(cl))?;
        packet_set.interface = Some(
            caps.name("interface_name")
                .ok_or(ParsingError::UnexpectedInput(cl))?
                .as_str()
                .to_owned(),
        );
        Ok(())
    }

    fn extract_filter(&mut self, caps: Captures) -> Result<()> {
        let cl = self.current_line;
        let packet_set = self
            .cur_packet_set_mut()
            .ok_or(ParsingError::UnexpectedState(cl))?;
        packet_set.filter = Some(
            caps.name("filter")
                .ok_or(ParsingError::UnexpectedInput(cl))?
                .as_str()
                .to_owned(),
        );
        Ok(())
    }

    fn extract_summary(&mut self, caps: Captures) -> Result<()> {
        self.leave_packet();
        let timestamp: NaiveDateTime;
        let interface: Option<String>;
        let direction: PacketDirection;
        if let Some(abs_time) = caps.name("abs_time") {
            let abs_time = abs_time.as_str();
            let pos = abs_time.find('.').unwrap_or(0);
            let format_str = format!("%Y-%m-%d %H:%M:%S.%{}f", abs_time.len() - pos - 1);
            timestamp = NaiveDateTime::parse_from_str(abs_time, &format_str)
                .map_err(|_| ParsingError::UnexpectedInput(self.current_line))?;
        } else if let Some(rel_time) = caps.name("rel_time") {
            let cl = self.current_line;
            let packet_set = self
                .cur_packet_set_mut()
                .ok_or(ParsingError::UnexpectedState(cl))?;
            let rel_time_secs: f64 = rel_time
                .as_str()
                .parse()
                .map_err(|_| ParsingError::UnexpectedInput(cl))?;
            timestamp = packet_set.start_time + Duration::nanoseconds((rel_time_secs * 1e9) as i64);
        } else {
            return Err(ParsingError::UnexpectedInput(self.current_line));
        }
        if let Some(intf_match) = caps.name("interface") {
            interface = Some(intf_match.as_str().to_owned());
        } else {
            interface = None
        }
        if let Some(dir_match) = caps.name("direction") {
            direction = dir_match
                .as_str()
                .parse()
                .map_err(|_| ParsingError::UnexpectedInput(self.current_line))?;
        } else {
            direction = PacketDirection::Unknown;
        }
        let cl = self.current_line;
        self.current_packet = Some(Packet::new(
            interface,
            direction,
            timestamp,
            caps.name("text")
                .map(|t| t.as_str().to_owned())
                .ok_or(ParsingError::UnexpectedInput(self.current_line))?,
            Vec::with_capacity(BUFFER_SIZE),
            self.current_set.ok_or(ParsingError::UnexpectedState(cl))?,
        ));
        Ok(())
    }

    fn extract_packet_bytes(&mut self, caps: Captures) -> Result<()> {
        let hex = caps
            .name("hex")
            .ok_or(ParsingError::UnexpectedInput(self.current_line))?
            .as_str();
        let hex: String = hex.chars().filter(|&c| !c.is_whitespace()).collect();
        if hex.len() % 2 != 0 {
            return Err(ParsingError::UnexpectedInput(self.current_line));
        }
        let packet = self.current_packet.as_mut();
        if let Some(p) = packet {
            p.data.extend(
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()),
            );
        }
        Ok(())
    }

    fn extract_rx_count(&mut self, caps: Captures) -> Result<()> {
        let cl = self.current_line;
        let packet_set = self
            .cur_packet_set_mut()
            .ok_or(ParsingError::UnexpectedState(cl))?;
        packet_set.rx_count = Some(
            caps.name("count")
                .ok_or(ParsingError::UnexpectedInput(cl))?
                .as_str()
                .parse()
                .or(Err(ParsingError::UnexpectedInput(cl)))?,
        );
        Ok(())
    }

    fn extract_drop_count(&mut self, caps: Captures) -> Result<()> {
        let cl = self.current_line;
        let packet_set = self
            .cur_packet_set_mut()
            .ok_or(ParsingError::UnexpectedState(cl))?;
        packet_set.drop_count = Some(
            caps.name("count")
                .ok_or(ParsingError::UnexpectedInput(cl))?
                .as_str()
                .parse()
                .or(Err(ParsingError::UnexpectedInput(cl)))?,
        );
        Ok(())
    }

    fn take_packet(&mut self) -> Option<Packet> {
        self.parsed_packet.take()
    }

    fn leave_packet(&mut self) {
        self.parsed_packet = self.current_packet.take();
        if let Some(_) = self.parsed_packet {
            if let Some(ps) = self.cur_packet_set_mut() {
                ps.packet_count += 1;
            }
        }
    }

    fn start_sniffer(&mut self) {
        let packet_set = PacketSet::default();
        self.current_set = Some(self.packet_sets.len());
        self.packet_sets.push(packet_set);
    }

    fn leave_sniffer(&mut self) {
        self.leave_packet();
        self.current_set = None;
    }

    fn parse_line(&mut self, line: &str) -> Result<()> {
        self.current_line += 1;
        let line = line.trim();
        match self.state {
            State::Out => {
                if let Some(caps) = INTERFACE_RE.captures(line) {
                    self.start_sniffer();
                    self.state = State::InSnifferHeader;
                    self.extract_interface(caps)?
                } else if let Some(caps) = PACKET_SUMMARY_RE.captures(line) {
                    self.start_sniffer();
                    self.state = State::InPacketSummary;
                    self.extract_summary(caps)?
                } else {
                }
            }
            State::InSnifferHeader => {
                if let Some(caps) = FILTER_RE.captures(line) {
                    self.extract_filter(caps)?
                } else if let Some(caps) = PACKET_SUMMARY_RE.captures(line) {
                    self.state = State::InPacketSummary;
                    self.extract_summary(caps)?;
                } else if line.is_empty() {
                    // Ignore blank lines
                } else {
                    self.leave_sniffer();
                    self.state = State::Out;
                }
            }
            State::InPacketSummary => {
                if let Some(caps) = PACKET_RE.captures(line) {
                    self.state = State::InPacketBytes;
                    self.extract_packet_bytes(caps)?
                } else {
                    // Append to the summary buffer, up to
                    // MAX_SUMMARY_LINES lines
                    if let Some(p) = self.current_packet.as_mut() {
                        if p.summary_lines < MAX_SUMMARY_LINES {
                            p.summary.push_str("\n");
                            p.summary.push_str(line);
                            p.summary_lines += 1;
                        } else {
                            self.state = State::InSnifferHeader;
                        }
                    }
                }
            }
            State::InPacketBytes => {
                if let Some(caps) = PACKET_RE.captures(line) {
                    self.extract_packet_bytes(caps)?
                } else if line.is_empty() {
                    // Ignore blank lines
                } else if let Some(caps) = PACKET_SUMMARY_RE.captures(line) {
                    self.state = State::InPacketSummary;
                    self.extract_summary(caps)?
                } else if let Some(caps) = RX_COUNT_RE.captures(line) {
                    self.state = State::InSnifferEnding;
                    self.extract_rx_count(caps)?;
                } else if !(line.is_empty() || line == "^C") {
                    // Ignore blank lines and lines containing ^C
                    self.leave_sniffer();
                    self.state = State::Out;
                }
            }
            State::InSnifferEnding => {
                self.state = State::Out;
                if let Some(caps) = DROP_COUNT_RE.captures(line) {
                    self.extract_drop_count(caps)?
                } else {
                }
                self.leave_sniffer();
            }
        }
        Ok(())
    }

    fn end_parsing(&mut self) {
        if self.state != State::Out {
            self.state = State::Out;
            self.leave_sniffer();
        }
    }
}

#[derive(Debug)]
pub struct PacketGenerator<R: Read> {
    parser: Parser,
    reader: BufReader<R>,
}

#[derive(Debug)]
pub enum PacketContext<'a> {
    Parsed(Packet, &'a PacketSet),
    EndOfSet(Option<(Packet, &'a PacketSet)>),
}

impl<R: Read> PacketGenerator<R> {
    pub fn new(reader: R) -> Self {
        Self {
            parser: Parser::new(),
            reader: BufReader::new(reader),
        }
    }

    pub fn next_packet_with_context(&mut self) -> Option<PacketContext> {
        let mut packet: Option<Packet> = None;
        let mut broke_out = false;
        let mut last_set: Option<usize> = None;
        let mut set_ended = false;
        for line in self.reader.by_ref().lines() {
            self.parser.parse_line(line.ok()?.as_str()).ok()?;
            if !set_ended {
                set_ended = last_set.is_some() && self.parser.current_set != last_set;
            }
            packet = self.parser.take_packet();
            last_set = self.parser.current_set;
            if packet.is_some() {
                broke_out = true;
                break;
            } else if set_ended {
                return Some(PacketContext::EndOfSet(None));
            }
        }
        if !broke_out {
            self.parser.end_parsing();
            packet = self.parser.take_packet();
        }
        if let Some(p) = packet {
            let ps = self.parser.packet_set(p.ps_index)?;
            if set_ended {
                Some(PacketContext::EndOfSet(Some((p, ps))))
            } else {
                Some(PacketContext::Parsed(p, ps))
            }
        } else {
            None
        }
    }

    pub fn next_packet(&mut self) -> Option<Packet> {
        let mut packet: Option<Packet> = None;
        let mut broke_out = false;
        for line in self.reader.by_ref().lines() {
            self.parser.parse_line(line.ok()?.as_str()).ok()?;
            packet = self.parser.take_packet();
            if packet.is_some() {
                broke_out = true;
                break;
            }
        }
        if !broke_out {
            self.parser.end_parsing();
            packet = self.parser.take_packet();
        }
        packet
    }
}

impl<R: Read> PacketGenerator<R> {
    pub fn iter(&mut self) -> BorrowingPacketIterator<R> {
        BorrowingPacketIterator::new(self)
    }
}

impl<R: Read> IntoIterator for PacketGenerator<R> {
    type Item = Packet;
    type IntoIter = PacketIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        PacketIterator::new(self)
    }
}

pub struct PacketIterator<R: Read> {
    pg: PacketGenerator<R>,
}

impl<R: Read> PacketIterator<R> {
    fn new(packet_generator: PacketGenerator<R>) -> Self {
        Self {
            pg: packet_generator,
        }
    }
}

impl<R: Read> Iterator for PacketIterator<R> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.pg.next_packet()
    }
}

pub struct BorrowingPacketIterator<'a, R: Read> {
    pg: &'a mut PacketGenerator<R>,
}

impl<'a, R: Read> BorrowingPacketIterator<'a, R> {
    fn new(packet_generator: &'a mut PacketGenerator<R>) -> Self {
        Self {
            pg: packet_generator,
        }
    }
}

impl<'a, R: Read> Iterator for BorrowingPacketIterator<'a, R> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.pg.next_packet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    lazy_static! {
        static ref SNIF_REL_ANY: &'static str = r#"interfaces=[any]
filters=[udp or ether proto 0x88cc]
0.513232 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

1.513232 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

2.513232 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

^C
3 packets received by filter
1 packets dropped by kernel

"#;
        static ref SNIF_ABS_ANY: &'static str = r#"interfaces=[any]
filters=[]
2020-04-03 00:30:41.791360 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

2020-04-03 00:30:42.791360 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

2020-04-03 00:30:43.791361 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

^C
3 packets received by filter
1 packets dropped by kernel

"#;
        static ref SNIF_TABS: &'static str = r#"interfaces=[any]
filters=[]
2020-04-03 00:30:41.791360 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000	 0000 0000 0002 0000 0000 0001 0800 4500	..............E.
0x0010	 0030 0001 0000 4011 66ba 0a00 0001 0a00	.0....@.f.......
0x0020	 0002 0400 0800 001c dfb3 0000 0000 0000	................
0x0030	 0000 0000 0000 0000 0000 0000 0000     	..............

"#;
        static ref SNIF_MUTLILINE_SUMMARY: &'static str = r#"interfaces=[any]
filters=[]
2020-04-03 00:30:41.791360 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
second line of summary
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

"#;
        static ref SNIF_NO_HEADER: &'static str = r#"2020-04-03 00:30:41.791360 port1 out 10.0.2.15.4430 -> 10.0.2.16.53: udp 20
0x0000   0000 0000 0002 0000 0000 0001 0800 4500        ..............E.
0x0010   0030 0001 0000 4011 66ba 0a00 0001 0a00        .0....@.f.......
0x0020   0002 0400 0800 001c dfb3 0000 0000 0000        ................
0x0030   0000 0000 0000 0000 0000 0000 0000             ..............

"#;
    }
    #[test]
    fn absolute_relative() {
        let gen = PacketGenerator::new(SNIF_REL_ANY.as_bytes());
        let ps = gen.into_iter().collect::<Vec<Packet>>();
        let first = &ps[0];
        let last = ps.last().unwrap();
        assert_eq!(
            (last.timestamp - first.timestamp)
                .num_nanoseconds()
                .unwrap(),
            ((2 as f64) * 1e9).floor() as i64
        );
    }

    #[test]
    fn absolute_timestamp() {
        let gen = PacketGenerator::new(SNIF_ABS_ANY.as_bytes());
        let ps = gen.into_iter().collect::<Vec<Packet>>();
        let first = &ps[0];
        let last = ps.last().unwrap();
        assert_eq!(
            first.timestamp,
            NaiveDate::from_ymd(2020, 4, 3).and_hms_nano(0, 30, 41, 791360000)
        );
        assert_eq!(
            last.timestamp,
            NaiveDate::from_ymd(2020, 4, 3).and_hms_nano(0, 30, 43, 791361000)
        );
    }

    #[test]
    fn two_sets() {
        let mut combined = SNIF_REL_ANY.to_owned();
        combined.push_str(&SNIF_ABS_ANY);
        let mut gen = PacketGenerator::new(combined.as_bytes());
        assert_eq!(gen.iter().collect::<Vec<Packet>>().len(), 6);
        assert_eq!(gen.parser.packet_set(0).unwrap().drop_count.unwrap(), 1);
        assert_eq!(gen.parser.packet_set(1).unwrap().drop_count.unwrap(), 1);
        assert_eq!(gen.parser.packet_set(0).unwrap().rx_count.unwrap(), 3);
        assert_eq!(gen.parser.packet_set(1).unwrap().rx_count.unwrap(), 3);
        assert_eq!(gen.parser.packet_set(0).unwrap().packet_count, 3);
        assert_eq!(gen.parser.packet_set(1).unwrap().packet_count, 3);
    }

    #[test]
    fn can_parse_tabs() {
        let gen = PacketGenerator::new(SNIF_TABS.as_bytes());
        let ps = gen.into_iter().collect::<Vec<Packet>>();
        let packet = &ps[0];
        assert_eq!(ps.len(), 1);
        assert_eq!(packet.interface, Some("port1".to_owned()));
    }

    #[test]
    fn filter() {
        let mut gen = PacketGenerator::new(SNIF_REL_ANY.as_bytes());
        let first = gen.next_packet_with_context().unwrap();
        if let PacketContext::Parsed(_, ps) = first {
            assert_eq!(ps.filter.as_ref().unwrap(), "udp or ether proto 0x88cc");
        }
    }

    #[test]
    fn multiline_summary() {
        let mut gen = PacketGenerator::new(SNIF_MUTLILINE_SUMMARY.as_bytes());
        let first = gen.next_packet_with_context().unwrap();
        if let PacketContext::Parsed(p, _) = first {
            assert_eq!(
                p.summary,
                "10.0.2.15.4430 -> 10.0.2.16.53: udp 20
second line of summary"
            );
            assert_eq!(p.data.len(), 62);
        } else {
            panic!("couldn't parse a valid packet")
        }
    }

    #[test]
    fn no_header() {
        let mut gen = PacketGenerator::new(SNIF_NO_HEADER.as_bytes());
        let first = gen.next_packet_with_context().unwrap();
        if let PacketContext::Parsed(p, _) = first {
            assert_eq!(p.data.len(), 62);
        } else {
            panic!("couldn't parse a valid packet")
        }
    }
}
