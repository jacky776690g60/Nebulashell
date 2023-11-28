'Nebula Protocol'

""" =================================================================
| nebulaprotocol.py -- Python/ethical_hacking/tools/nebulaprotocol.py
|
| Created by Jack on 20/11/2023
| Copyright © 2023 jacktogon. All rights reserved.
================================================================= """

import struct
import socket
from typing import Generator, Tuple
from enum import IntEnum


NE_HEADER_FORMAT = '>I4sH4sHIBI'
'''
- `>`: big-endian
- `I`: unsigned integer (data length)
- `4s`: 4 bytes (source address)
- `H`: unsigned short (source port)
- `4s`: 4 bytes (destination address)
- `H`: unsigned short (destination port)
- `I`: unsigned integer (sequence number)
- `B`: 1 byte unsigned char (TCP flags)
- `I`: unsigned short (checksum)
'''
NE_HEADER_SIZE = struct.calcsize(NE_HEADER_FORMAT)
NE_FOOTER = b'\r\n\r\n' # End-of-message marker


MAX_ACK_TIMEOUT = 100 
"milliseconds"
MAX_ACK_RETRIES = 100




class NE_Flags(IntEnum):
    '''Nebula Protocol Flags'''
    # ~~~~~~~~ original TCP flags ~~~~~~~~
    FIN = 0x01
    "Finish (1 in decimal)"
    SYN = 0x02
    "Synchronize (2 in decimal)"
    RST = 0x04
    "Reset (4 in decimal)"
    PSH = 0x08
    "Push Function (8 in decimal)"
    ACK = 0x10
    "Acknowledgment (16 in decimal)"
    URG = 0x20
    "Urgent Pointer (32 in decimal)"
    ECE = 0x40
    "ECN-Echo (64 in decimal)"
    CWR = 0x80
    "Congestion Window Reduced (128 in decimal)"
    # ~~~~~~~~ Additional ~~~~~~~~
    NS = 0x100
    "Nonce Sum (256 in decimal)"
    Reserved = 0x200
    "Reserved (512 in decimal)"



class NebulaPacket:
    '''
    A class for constructing and handling network packets, primarily operating 
    at the Network (Layer 3) and Transport (Layer 4) layers of the OSI model, 
    with potential applications extending to the Application Layer (Layer 7) 
    for file transfers.

    This class encapsulates key elements of network communication, such as 
    source and destination IP addresses (Layer 3) and transport-level details 
    like port numbers, sequence numbers, and TCP flags (Layer 4). It is primarily
    designed for network packet manipulation and transmission, but can also be 
    used in higher-level applications, such as sending files (PDFs, PNGs), which
    are part of the Application Layer.
    '''
    def __init__(self, 
        src_addr: str,
        src_port: int, 
        dest_addr: str,
        dest_port: int,
        seq_num: int,
        flag: bytes,
        checksum: int,
        data: bytes
    ):
        self.data_len     = len(data)
        self.src_port     = src_port
        self.dest_port    = dest_port
        self.src_addr     = src_addr
        self.dest_addr    = dest_addr
        self.seq_num      = seq_num
        self.flag         = flag
        self.checksum     = checksum
        self.data         = data
        
    def __repr__(self):
        return (f"NebulaPacket(src_addr={self.src_addr!r}, src_port={self.src_port}, "
                f"dest_addr={self.dest_addr!r}, dest_port={self.dest_port}, "
                f"seq_num={self.seq_num}, flag={self.flag}, "
                f"checksum={self.checksum}, data={self.data})")

    def __str__(self):
        return (f"NebulaPacket:\n"
                f"  Source Address: {self.src_addr}, Port: {self.src_port}\n"
                f"  Destination Address: {self.dest_addr}, Port: {self.dest_port}\n"
                f"  Sequence Number: {self.seq_num}, Flag: {self.flag}\n"
                f"  Checksum: {self.checksum}, Data Length: {self.data_len} bytes")


    def pack_data(self) -> bytes:
        '''
        Pack data with extended header and footer
        ```
        header + data + footer -> bytes
        '''
        header = struct.pack(
            NE_HEADER_FORMAT, 
            len(self.data),  
            socket.inet_aton(self.src_addr),  # Convert IP addresses to bytes
            self.src_port, 
            socket.inet_aton(self.dest_addr), # Convert IP addresses to bytes
            self.dest_port,
            self.seq_num,
            self.flag,
            self.checksum
        )
        return header + self.data + NE_FOOTER
    
    def is_flag_set(self, flag: NE_Flags) -> bool:
        return bool(self.flag & flag)
    
    @staticmethod
    def calc_checksum(self, data: bytes) -> int:
        # TODO: implement checksum
        return 0
    
    



class NebulaProtocol:
    
    def __init__(self,
        sock: socket.socket,
        src_addr: str,
        src_port: int,
        dest_addr: str,
        dest_port: int,
        buffer_size: int
    ) -> None:
        self.sock        = sock
        self.src_addr    = socket.gethostbyname(src_addr)
        self.src_port    = src_port
        self.dest_addr   = socket.gethostbyname(dest_addr)
        self.dest_port   = dest_port
        self.buffer_size = buffer_size


    def __recv(self, n: int) -> bytes | None:
        '''receive n bytes from the socket'''
        data = bytearray()
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        return bytes(data)


    # =============================
    # one packet sender / receiver
    # =============================
    def send_packet(self, data: bytes, seq_num: int=0, flag=NE_Flags.SYN):
        '''Send one `NebulaPacket`'''
        ne_packet = NebulaPacket(
            self.src_addr, self.src_port,
            self.dest_addr, self.dest_port,
            seq_num=seq_num,
            flag=flag,
            checksum=0,
            data=data
        )
        bytes_to_sent = ne_packet.pack_data()
        total_sent = 0
        while total_sent < len(bytes_to_sent):
            sent = self.sock.send(bytes_to_sent[total_sent:])
            if sent == 0: raise RuntimeError("Socket connection broken")
            total_sent += sent


    def recv_packet(self) -> 'NebulaPacket' :
        '''try receive one `NebulaPacket`'''
        # ~~~~~~~~ get metadata first ~~~~~~~~
        raw_header = self.__recv(NE_HEADER_SIZE)
        if not raw_header: return None
        data_length, src_addr_bytes, src_port, dest_addr_bytes, dest_port, seq_num, flag, checksum = struct.unpack(NE_HEADER_FORMAT, raw_header)

        
        src_addr  = socket.inet_ntoa(src_addr_bytes)
        dest_addr = socket.inet_ntoa(dest_addr_bytes)
        # ~~~~~~~~ get actual data ~~~~~~~~
        data = self.__recv(data_length)
        
        # if not data: return None
        # TODO: Add checksum validation here

        # ~~~~~~~~ get footer ~~~~~~~~
        footer = self.__recv(len(NE_FOOTER))
        if footer != NE_FOOTER: raise ValueError("Invalid message footer")

        return NebulaPacket(src_addr, src_port, dest_addr, dest_port, seq_num, flag, checksum, data)


    def send_ack_packet(self, packet: 'NebulaPacket'):
        
        ack_packet = NebulaPacket(
            self.src_addr, self.src_port,
            packet.src_addr, packet.src_port,
            seq_num=packet.seq_num,  # Echo the sequence number
            flag=NE_Flags.ACK,
            checksum=packet.checksum, # Implement checksum calculation as needed
            data=b''
        )
        
        self.sock.send(ack_packet.pack_data())


    def wait_ack_packet(self, expected_seq_num: int) -> bool:
        self.sock.settimeout(MAX_ACK_TIMEOUT)
        ack_packet = self.recv_packet()
        if ack_packet and ack_packet.is_flag_set(NE_Flags.ACK) and ack_packet.seq_num == expected_seq_num:
            return True
        return False



    # =============================
    # multi packets sender / receiver
    # =============================
    def send_data_stream(self, data: bytes) -> None:
        '''
        Send segmented data based on buffer_size

        Example:
        --------
        >>> NEP = NebulaProtocol(...)
        ... NEP.send_data_stream(large_bytes)
        '''
        seq_num = 0
        while data:
            segment, data = data[:self.buffer_size], data[self.buffer_size:]
            flag = NE_Flags.FIN if not data else NE_Flags.ACK
            self.send_packet(segment, seq_num, flag)

            ack_received = False
            for _ in range(MAX_ACK_RETRIES):
                try:
                    ack_received = self.wait_ack_packet(seq_num)
                    if ack_received: break
                except socket.timeout:
                    self.send_packet(segment, seq_num, flag)

            if not ack_received:
                raise RuntimeError("ACK not received after maximum retries")

            seq_num += 1
        
    
    def recv_data_stream(self) -> Tuple[bytes, NebulaPacket]:
        '''
        Receive and combine segmented data

        Example:
        ---------
        >>> NEP = NebulaProtocol(...)
        ... large_bytes, last_packet = NEP.recv_data_stream()
        '''
        combined_data = bytearray()
        last_packet = None
        while True:
            packet = self.recv_packet()
            if packet is None: break

            combined_data.extend(packet.data)
            last_packet = packet

            self.send_ack_packet(packet)
            if packet.is_flag_set(NE_Flags.FIN): break

        return bytes(combined_data), last_packet










    def send_data_stream_generator(self, generator: Generator[bytes, None, None]) -> None:
        buffer = b''
        seq_num = 0
        for data_segment in generator:
            buffer += data_segment
            
            while len(buffer) >= self.buffer_size:
                self.send_packet( buffer[:self.buffer_size], seq_num )
                buffer = buffer[self.buffer_size:]

                ack_received = False
                for _ in range(MAX_ACK_RETRIES):
                    try:
                        ack_received = self.wait_ack_packet(seq_num)
                        if ack_received: break
                    except socket.timeout:
                        self.send_packet(buffer[:self.buffer_size], seq_num)

                if not ack_received:
                    raise RuntimeError("ACK not received after maximum retries")

                seq_num += 1

        self.send_packet(buffer if buffer else b'', seq_num, NE_Flags.FIN)




    def recv_data_stream_generator(self) -> Generator[bytes, None, None]:
        buffer = b''
        while True:
            packet = self.recv_packet()
            if packet is None: break

            buffer += packet.data
            if len(buffer) >= self.buffer_size or packet.is_flag_set(NE_Flags.FIN):
                yield buffer
                buffer = b''

            self.send_ack_packet(packet)
            if packet.is_flag_set(NE_Flags.FIN): break
