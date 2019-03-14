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

* find a synchronization word (0xf2e83553)
* fill a buffer
* stop filling the buffer when another synchronization word is found
* perform bytes unstuffing if needed
* compare the length of the buffer with the length given in the HRDL header
  - if there are not enough bytes, discard the packet
  - if there are too many bytes, discard the trailing zeros (that should come
    from 1-4 VCDU fillers)
  - otherwise do nothing and go to the next step
* optionally, verify that the checksum found in the trailer of the HRDL packet
  matches the calculated one. If the checksums mismatch discard the packet if
  requested
* repeat the process until end of stream
