# snifos

`snifos` converts FortiOS sniffer output to
[pcapng](https://github.com/pcapng/pcapng). It's written in Rust, and
tries to be fast and flexible.

# Features

- Generates pcapng files, with interface name and packet direction
  information (if that information is available in the input file).
- Supports absolute and relative timestamps.
- Can extract multiple pcapng files from a single input file.
  (`--split`)
- Supports the "raw IP" link type (`LINKTYPE_RAW`), useful for
  converting packets captured on tunnel interfaces. (`--raw`)
- Memory and storage efficient. It doesn't generate an intermediate
  file, nor does it store all packets in memory.
- Single binary, with no runtime dependency, for Linux, MacOS and
  Windows.

# Usage

```
$ ./snifos -h
snifos 0.1.0
A tool for converting FortiOS sniffer output to pcapng

USAGE:
    snifos [FLAGS] [OPTIONS] --input <INPUT> --output <OUTPUT>

FLAGS:
    -h, --help       Prints help information
    -s, --split      Create a new pcapng file for each sniffer run in the input
    -V, --version    Prints version information
    -v, --verbose    Enables verbose output

OPTIONS:
    -i, --input <INPUT>      Input file (use - for stdin)
    -o, --output <OUTPUT>    Output file (use - for stdout)
    -r, --raw <RAW>...       Regex matching interfaces converted with the raw link type
```

## Generating a single output pcapng file

```
$ ./snifos -i test.txt -o test.pcapng
Creating a new file: test.pcapng
```

## Generating one pcapng file for each sniffer run in the input file

If the input file contains the output of multiple instances of the
sniffer command, you can split it into multiple pcapng files.

```
$ ./snifos -i test.txt -o test --split
Creating a new file: test-1.pcapng
Creating a new file: test-2.pcapng
```

In this case, the `-o` argument takes a prefix. This prefix is used to
generate the output file names.

## Raw link type

If captured packets on some interfaces in the input file don't contain
the Ethernet header, you can use the `--raw` (or `-r`) to convert them
properly. Any interface names matching regular expressions passed in
this way, are treated as "raw IP" links. This is especially useful
when converting packets captured on tunnel interface (e.g. IPsec).

```
$ ./snifos -i test.txt -o test.pcapng --raw 'tunnel.*'
Creating a new file: test.pcapng
```

## Timestamps

Relative timestamps are converted to absolute timestamps before being
written to the output file. This is done by adding the relative time
to a "start" time (which is the system clock time at the time parsing
starts for the output of a sniffer run).

# Performance

Quick unscientific comparison with the Perl-based converter (that uses `text2pcap` internally):

```
$ uname -a
Linux leela 5.10.16-arch1-1 #1 SMP PREEMPT Sat, 13 Feb 2021 20:50:18 +0000 x86_64 GNU/Linux

$ time target/release/snifos -i large.txt -o large.pcapng
Creating a new file: large.pcapng

real    0m8.450s
user    0m8.282s
sys     0m0.163s

$ tcpdump -n --count -r large.pcapng 
reading from file large.pcapng, link-type EN10MB (Ethernet), snapshot length 262144
100000 packets
$ rm large.pcapng 

$ time ./fgt2eth.pl -in large.txt -out large.pcap

real    1m56.745s
user    1m31.995s
sys     1m2.213s

$ tcpdump -n --count -r large.pcap
reading from file large.pcap, link-type EN10MB (Ethernet), snapshot length 262144
100000 packets
```

# License

This project is licensed under the MIT license.

See [LICENSE-MIT](LICENSE-MIT) for details.
