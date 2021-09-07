# feproxy
Fallen Earth man-in-the-middle proxy

## Purpose
Proof of concept project that implements the Fallen Earth network 
cipher protocol. `feproxy` acts as a man-in-the-middle proxy that 
strips the encryption of packets in realtime for plaintext viewing and 
further reverse engineering.

## Reverse Engineering
Documentation of the network cipher was accomplished by disassembling 
the game with IDA Pro and following and understanding the logic 
handling network sockets. This necessitated a thorough understanding of 
C++ (what the game was written in) and how it translated to machine 
code (x86 assembly). A pseudo-C reimplementation of the logic can be 
found in the accompanying [Reversing.md](Reversing.md) document.
