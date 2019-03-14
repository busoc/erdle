# erdle

The erdle tool suite can be used for just anything that can be done on VCDU (aka
CADU) packets.

Started as small in-house [scripts](https://github.com/busoc/cadus), they have
first evolved to a simple tool able to dissect VCDU packets and then continue to
grow to a full-featured tool able to reproduce features of the HRD-FE and some
of the HRDP (with some small related tools).

Features of erdle can be divided into two main areas:

* reporting and debugging packets
* receiving VCUDS and forwarding HRDL packets

erdle comes with a large set of commands that ranges from forwarding reassembled
HRDL packets to counting cadus present in a set of files, eg:

* relay
* store
* list
* index
* and many others...

At the core of erdle comes the re-assembling of HRDL packets from a bunch of
VCDU packets. To perform this task, erdle can use a set of files or UDP packets
stream. the procedure is as follows:

1. find a synchronization word (0xf2e83553)
2. fill a buffer
3. stop filling the buffer when another synchronization word is found
4. perform bytes unstuffing if needed
5. compare the length of the buffer with the length given in the HRDL header
  - if there are not enough bytes, discard the packet
  - if there are too many bytes, discard the trailing zeros (that should come
    from 1-4 VCDU fillers)
  - otherwise do nothing and go to the next step
6. optionally, verify that the checksum found in the trailer of the HRDL packet
  matches the calculated one. If the checksums mismatch discard the packet if
  requested
7. repeat the process until end of stream

# erdle store

the store command of erdle can be used, as its name implies, to store under a
dedicated directory, the two kind of packets that erdle can deal with (but not
both at the same time):

* HRDL packets
* VCDU packets

According to the type of packets to be written on disk, this command will adapt
the format used to store these in files. The file format is mainly a binary flat
file with some extra headers (specific to its type) added before each packets.

HRDL packets will be store as the HRDP does for this kind of packets in rt files.
This way existing tools able to decode rt files can also be used to decode and/or
manipulate files created by the store command.

VCDU packets will be store as the HRD-FE does when using its built-in dump
capabilities.

Files written by this command are automatically rotated according to one of the
following conditions (depending also of the options set):

* number of packets written reached threshold set
* number of bytes written reached threshold set
* time interval elapsed between two rotations
* timeout since last write

The following options can be given to the store command:

```
  -c          use given configuration file to load options
  -i INTERVAL time between automatic file rotation
  -t TIMEOUT  timeout before forcing file rotation
  -s SIZE     max size (in bytes) of a file before triggering a rotation
  -c COUNT    max number of packets in a file before triggering a rotation
  -b BUFFER   size of buffer between incoming cadus and reassembler
  -p PAYLOAD  identifier of source payload
  -q SIZE     size of the queue to store reassemble packets
  -k          store HRDL packets even if they are corrupted
```

A configuration file (using [toml](https://github.com/toml-lang/toml)) can also
be use instead of the command line options if multiple instance of this command
should runned simulatenously (eg when they have to be managed by systemd)

```
# sample configuration file for store command

address   = "udp://:10015"
datadir   = "var/hrdp/vmu"

[hrdl]
payload = 2
buffer  = 67108864
queue   = 1024
keep    = false

[storage]
interval  = 300
timeout   = 10
maxsize   = 0
maxcount  = 0
```
