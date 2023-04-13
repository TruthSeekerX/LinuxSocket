# Introduction

This project is meant for studying IITS3105-3009 Socket Programming course at VAMK. The objectives are:

* Understanding the socket in Windows OS and GNU/Linux
* Get familiar with libraries: WinSock2, sys/socket
* Practice C programming skills, understand better endianess, struct, union data structures.

There are experiments on GNU/Linux system, such as self defined ethernet frame and IP packet structures. They are not meant as a production implementation. Linux kernel already includes best codes check them out on github.

# Socket in GNU/Linux

In general, a socket is a endpoint that provides a way for inter process communication (IPC). There are two (as far as I know by now) types of sockets: **Network Socket** and **Unix Domain Socket** (**UDS**). As the name suggests a network socket support the IPC over a network. Network sockets could be furthur diveded into **raw sockets**, **TCP socket** and **UDP socket**. An UDS supports the IPC within the same machine. UDS could be furthur categorised into stream socket, datagram socket and sequenced-packet socket.

# Network Socket

## Raw Socket

Raw socket has the direct access to the netwrok interface card (NIC), from which the application could receive or send an data link layer frame. This is considered very dangerous, because with raw socket the application could exam, listen, alter, craft the network data as desire. Therefore administrative privilege is required for using raw socket. 

## TCP Socket

TCP socket as the name suggest, is provides support for TCP protocol (on transport layer). TCP is a stream-oriented and stateful (connection-based) protocol within Internet Protocol suit. It is suited in application where reliability is most important factor. TCP connect starts with 3-way handshake (SYN, SYN-ACK, ACK) and ends with 4-way handshake (FIN, ACK, FIN, ACK).

## UDP socket

UDP socket supports UDP protocol. UDP is a datagram-oriented and stateless (connection-less) protocol from Internet Protocol suit. Datagram is an independent, self-contained packets of data. UDP provides a lightweight, low-overhead connection between two endpoints. Therefore it offers very low latency communication. However, it is not as reliable as TCP. UDP doesn't offer any mechanism to handle exceptions such as lost packet, incorrect order. UDP is used when low latency is more important than data integrity, such as VoIP, online gaming, audio/video streaming.

## SCTP socket

Stream Control Transmission Protocol is also a transport layer protocol. It is Message-based multi-streaming protocol. 

[https://en.wikipedia.org/wiki/Network_socket]()


# Unix Domain Socket

A Unix Domain Socket is a type of socket that enables communication between processes running on the same machine, using the local file system as the underlying transport mechanism instead of the network. 

## SOCK_STREAM

Stream-oriented socket, comparable to TCP socket.

## SOCK_DGRAM

Datagram-oriented socket, comparable to UDP socket.

## SOCK_SEQPACKET

sequenced-packet socket that is connection-oriented, preserves message boundaries, and delivers messages in the order that they were sent, comparable to SCTP socket.

[https://en.wikipedia.org/wiki/Unix_domain_socket]()
