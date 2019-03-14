# erdle

The erdle tool suite can be used for just anything that can be done on VCDU (aka
CADU) packets.

Started as small in-house [scripts](https://github.com/busoc/cadus), they have
first evolved to a simple tool able to dissect VCDU packets and then continue to
grow to a full-featured tool able to reproduce features of the HRD-FE and some
of the HRDP (with some small related tools).

Features of erdle can be divided into two main areas:

* reporting and debugging
* networking (TBD)

erdle come with a full set of commands that ranges from forwarding reassembled
HRDL packets to counting cadus present in a set of files:

* relay
* store
* list
* index
* and many others...
