#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dataclasses import dataclass
from typing import List
import sys
import struct
import zlib

def u16(data):
    return struct.unpack(">H", data)[0]

def u32(data):
    return struct.unpack(">I", data)[0]

def downloadlib_decipher(ct: bytes) -> bytes:
  key = 904
  length = len(ct)
  pt = bytearray()

  n, i = 0, 0
  while length > 0:
    blocksz = min(length, 128)
    for _ in range(blocksz):
      pt.append(ct[i] ^ ((key >> 8) & 0xff))
      key += ct[i] + 38400 + 163

      i, n = i + 1, n + 1
      if n > 255:
        n = 0
        key = 904
    length -= blocksz
  return bytes(pt)

class SDDL:
  @dataclass
  class Module:
    @dataclass
    class Info:
      field_0: int
      flags: int
      module_type: int
      compressed_length: int
      length: int
      crc: int
      offset: int

    name: str
    info: "SDDL.Module.Info"
    data: bytes

    def extract_data(self):
      data = self.data
      if (self.info.flags & 2) != 0:
        data = downloadlib_decipher(data)
      if (self.info.flags & 1) != 0:
        data = zlib.decompress(data)
      return data

  @dataclass
  class Entry:
    name: str
    data: bytes
    
    @property
    def size(self):
        return len(self.data)

    def parse_module(self, offset):
      # Useless validation header
      # header = entry.data[:32]
      # magic = header[:4]
      # items = [header[4], header[5], header[6], header[7]]
      # items += [u32(header[8:12]), u32(header[12:16]), u32(header[16:20]), u32(header[20:24]), u32(header[24:28])]
      # items += [u16(header[28:30]), u16(header[30:32])]
      # header_items = items
      
      header2 = self.data[32:32+16]
      items = [u16(header2[:2]), header2[2], header2[3], u32(header2[4:8]), u32(header2[8:12]), u32(header2[12:16])]
      header2_items = items

      info = SDDL.Module.Info(header2_items[0], header2_items[1], header2_items[2], header2_items[3]-offset, header2_items[4], header2_items[5], offset)
      
      assert len(self.data)==header2_items[3]+48, f"invalid module size: expected {header2_items[3]+48} but got {len(self.data)}"
      return SDDL.Module(self.name, info, self.data[48:])

  def __init__(self, sddl: bytes, crypto_key: bytes):
    self.sddl = sddl
    crypto_key = downloadlib_decipher(crypto_key)
    self.key = crypto_key[:16]
    self.iv = crypto_key[16:]
    print(f"AES Key: {self.key.hex()}")
    print(f"AES IV: {self.iv.hex()}")
    print("SDDL:")
    self.entries = self.read_entries()

  # Decrypts data using the crypto_key
  def decrypt(self, data: bytes) -> bytes:
    aes = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
    return unpad(aes.decrypt(data), 16)
  
  # Returns number of entries in the SDDL
  def read_header(self) -> int:
    data = self.sddl[:32]
    data = downloadlib_decipher(data)
    field_8 = int(data[8:12].decode())
    field_C = int(data[12:16].decode())
    return field_8 + field_C + 1

  def read_entries(self) -> List[Entry]:
    n = self.read_header()
    print(f" {n} entries:", end=' ')
    index = 32
    entries = []
    for _ in range(n):
      header = self.decrypt(self.sddl[index:index+32])
      index += 32
      name = header[:12]
      name = name[:name.index(b'\x00')]
      name = name.decode()
      size = int(header[12:].decode())
      data = self.sddl[index:index+size]
      index += size

      # A guess was made that the data itself is also encrypted and it was correct :) 
      data = self.decrypt(data)
      entries.append(SDDL.Entry(name, data))
    
    print(" ".join(map(lambda e: e.name, entries)))
    return entries

def main():
  if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} /path/to/SDDL.SEC /path/to/crypto_key",
      file=sys.stderr)
    sys.exit(1)

  with open(sys.argv[1], "rb") as file:
    sddl = file.read()
  with open(sys.argv[2], "rb") as file:
    crypto_key = file.read()

  sddl = SDDL(sddl, crypto_key)
  modules = [e.parse_module(512) for e in sddl.entries if e.name.startswith("PEAKS")]

  sddl_tmp = bytes()
  for module in modules:
    data = module.extract_data()
    copy_info = [u32(data[5:9]), u32(data[1:5]), u32(data[9:13])]
    print(f"{module.name} flags={module.info.flags} type={module.info.module_type} data_start={copy_info[0]} copy_offset={copy_info[1]} length={copy_info[2]}")

    sddl_tmp += data[copy_info[0]:copy_info[0]+copy_info[2]]
  
  with open("/tmp/SDDL.TMP", "wb") as f:
    f.write(sddl_tmp)

if __name__ == '__main__':
  main()