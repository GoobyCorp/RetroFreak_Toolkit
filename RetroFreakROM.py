#!/usr/bin/env python3

from os import urandom
from argparse import ArgumentParser
from os.path import isfile, join, basename
from struct import unpack, pack_into, unpack_from
from binascii import unhexlify, crc32, hexlify as _hexlify

# pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import MD5, SHA1
from Cryptodome.Util.Padding import unpad
from Cryptodome.Signature import PKCS1_v1_5

ROM_MAGIC = b"RFRK"
ROM_SECRET = unhexlify("6F5BC7F1068C3D60D6A62E757739453A")
REQUEST_MAGIC = b"WPR2"
REQUEST_SECRET = unhexlify("D7A1066CE2DC0D5A8636D1E8D0965E90")
REQUEST_FILE = "retrofreak-update-request.dat"
REQUEST_PUB_KEY_FILE = "request.pub"
REQUEST_SIZE = 192

REQUEST_PUB_KEY = None

hexlify = lambda b: _hexlify(b).decode("utf8").upper()

def read_file(filename: str) -> bytes:
	with open(filename, "rb") as f:
		data = f.read()
	return data

def write_file(filename: str, data: (bytes, bytearray)) -> None:
	with open(filename, "wb") as f:
		f.write(data)

def decrypt_update_request(data: (bytes, bytearray)) -> (bytes, bytearray):
	global REQUEST_SECRET, REQUEST_MAGIC, REQUEST_PUB_KEY

	assert len(data) == REQUEST_SIZE, "Invalid update request size"
	iv = data[:16]
	cipher = AES.new(REQUEST_SECRET, AES.MODE_CBC, iv)
	enc_data = data[16:]  # array + signature
	dec_data = unpad(cipher.decrypt(enc_data), AES.block_size)
	body = dec_data[:-REQUEST_PUB_KEY.size_in_bytes()]  # UNIQUE_MAGIC + DNA
	signature = dec_data[-REQUEST_PUB_KEY.size_in_bytes():]
	# verify file magic
	assert body[:4] == REQUEST_MAGIC, "Invalid update request magic"
	# verify signature
	verifier = PKCS1_v1_5.new(REQUEST_PUB_KEY)
	assert verifier.verify(SHA1.new(body), signature), "Invalid signature"
	(magic, dna, sys_fw_ver, ver_code, pcba_rev) = unpack("<4s 16s 3I", body)
	return dna

def derive_rom_key(dna: (bytes, bytearray)) -> bytes:
	global ROM_SECRET

	digest = bytearray(MD5.new(dna).digest())
	for i in range(16):
		digest[i] ^= ROM_SECRET[i]
	return bytes(digest)

def decrypt_rom(dna: (bytes, bytearray), data: (bytes, bytearray)) -> (bytes, bytearray):
	global ROM_MAGIC

	key = derive_rom_key(dna)
	assert data[:4] == ROM_MAGIC, "Invalid magic"
	iv = data[0x10:0x10 + 16]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	dec_data = cipher.decrypt(data[0x20:0x20 + 0x1E0])
	(magic, rom_crc, rom_size) = unpack_from("<4s 2I", dec_data, 0)
	assert magic == ROM_MAGIC, "Invalid magic"
	dec_data = cipher.decrypt(data[0x200:0x200 + rom_size])
	assert rom_crc == crc32(dec_data), "Invalid ROM checksum"
	return dec_data

def encrypt_rom(dna: (bytes, bytearray), data: (bytes, bytearray)) -> (bytes, bytearray):
	global ROM_MAGIC

	key = derive_rom_key(dna)
	hdr_buf = bytearray(urandom(0x200))
	(iv,) = unpack_from("16s", hdr_buf, 0x10)
	pack_into("<4s", hdr_buf, 0, ROM_MAGIC)
	pack_into("<4s 2I", hdr_buf, 0x20, ROM_MAGIC, crc32(data), len(data))
	cipher = AES.new(key, AES.MODE_CBC, iv)
	pack_into(f"{0x1E0}s", hdr_buf, 0x20, cipher.encrypt(hdr_buf[0x20:0x20 + 0x1E0]))
	return hdr_buf + cipher.encrypt(data)

def main() -> None:
	global REQUEST_PUB_KEY, REQUEST_PUB_KEY_FILE, ROM_MAGIC, REQUEST_FILE

	REQUEST_PUB_KEY = RSA.import_key(read_file(join("Keys", REQUEST_PUB_KEY_FILE)))

	parser = ArgumentParser(description="A script to encrypt/decrypt ROM's to/from the RetroFreak")
	parser.add_argument("ifile", type=str, help="The ROM to read from")
	parser.add_argument("-o", type=str, help="The ROM file to write to")
	parser.add_argument("-s", "--serial", type=str, help="The serial number you want to use")
	parser.add_argument("-k", "--keyfile", type=str, default=REQUEST_FILE, help="The update request file to read from")
	args = parser.parse_args()

	assert isfile(args.ifile), "The specified ROM file doesn't exist"

	if args.serial:
		dna = unhexlify(args.serial)
	elif args.keyfile and isfile(args.keyfile):
		dna = decrypt_update_request(read_file(args.keyfile))
	else:
		raise FileNotFoundError("-s (--serial) or -k (--keyfile) is required but not provided")

	print("Serial #: " + hexlify(dna))

	rom_data = read_file(args.ifile)
	if rom_data[:4] == ROM_MAGIC:  # encrypted
		print(f"Decrypting \"{basename(args.ifile)}\"...")
		write_file(args.o if args.o else args.ifile, decrypt_rom(dna, rom_data))
	else:  # plaintext
		print(f"Encrypting \"{basename(args.ifile)}\"...")
		write_file(args.o if args.o else args.ifile, encrypt_rom(dna, rom_data))
	print("Done!")


if __name__ == "__main__":
	main()