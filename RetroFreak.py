#!/usr/bin/env python3

__author__ = "Visual Studio"

from ctypes import *
from enum import IntEnum
from tarfile import TarFile
from datetime import datetime
from bz2 import BZ2Decompressor
from math import floor, log, pow
from os import urandom, rename, remove
from os.path import join, isfile, basename
from struct import pack, unpack, pack_into, unpack_from
from binascii import hexlify as _hexlify, unhexlify, crc32

from StreamIO import *

# pip install pycryptodomex
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA1, MD5
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Util.strxor import strxor
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Util.Padding import pad, unpad

# globals
UPDATE_PUB_KEY = None
REQUEST_PRV_KEY = None

# constants
DEBUG = True
BUFF_SIZE = 16384
BLOCK_SIZE = 8192
OUTPUT_DIR = "Output"
SHARED_MAGIC = unhexlify("DFC03713")
REQUEST_MAGIC = b"WPR2"
ROM_MAGIC = b"RFRK"
RKFW_MAGIC = b"RKFW"
RKFW_BOOT_MAGIC = b"BOOT"
ANDROID_BOOT_MAGIC = b"ANDROID!"
REQUEST_FILE = "retrofreak-update-request.dat"
APP_UPDATE_FILE = "retrofreak-update.bin"
SYS_UPDATE_FILE = "retrofreak-system-update.img"
UPDATE_PUB_KEY_FILE = "update.pub"
REQUEST_PRV_KEY_FILE = "request.prv"

# secrets
# ROM secret
ROM_SECRET = unhexlify("6F5BC7F1068C3D60D6A62E757739453A")
# secret used to decrypt system update files (not app updates)
SYSTEM_SECRET = unhexlify("9B589B3E3ACC4E2DC5389E7FF0C7C0BE")
# used to encrypt console's DNA (serial #) for generating update requests
REQUEST_SECRET = unhexlify("D7A1066CE2DC0D5A8636D1E8D0965E90")
# RockChip RC4 key
RKFW_KEY = unhexlify("7c4e0304550509072d2c7b38170d1711")

# utilities
hexlify = lambda b: _hexlify(b).decode("utf8").upper()

# enums
class RKFW_ChipID(IntEnum):
	RK3066 = 0x60
	RK3188 = 0x70

class RKFW_Type(IntEnum):
	UPDATE = 0
	RKAF = 1

# structures
class RKFW_Header(Structure):
	_pack_ = True
	_fields_ = [
		("Magic", c_byte * 4),
		("HdrLen", c_uint16),
		("Version", c_uint32),
		("Code", c_uint32),
		("Year", c_uint16),
		("Month", c_uint8),
		("Day", c_uint8),
		("Hour", c_uint8),
		("Minute", c_uint8),
		("Second", c_uint8),
		("ChipID", c_uint32),
		("LoadOff", c_uint32),
		("LoadLen", c_uint32),
		("DataOff", c_uint32),
		("DataLen", c_uint32),
		("Unk0", c_uint32),
		("Type", c_uint32),
		("SysFStype", c_uint32),
		("BackupEnd", c_uint32),
		("Reserved", c_ubyte * 45)
	]

class StageRec(Structure):
	_pack_ = True
	_fields_ = [
		("RecType", c_uint8),
		("RecOff", c_uint32),
		("RecLen", c_uint8),
	]

class RKBoot_Header(Structure):
	_pack_ = True
	_fields_ = [
		("Magic", c_byte * 4),
		("HdrLen", c_uint16),
		("Version", c_uint32),
		("Code", c_uint32),
		("Year", c_uint16),
		("Month", c_uint8),
		("Day", c_uint8),
		("Hour", c_uint8),
		("Minute", c_uint8),
		("Second", c_uint8),
		("ChipID", c_uint32),
		("StageRecs", StageRec * 4),
		("Reserved", c_ubyte * 53)
	]

class RKBootFileRec(Structure):
	_pack_ = True
	_fields_ = [
		("FileRecLen", c_uint8),
		("FileNum", c_uint32),
		("FileName", c_wchar * 20),
		("FileOff", c_uint32),
		("FileSize", c_uint32),
		("Unk0", c_uint32)
	]

class UpdFile(Structure):
	_pack_ = True
	_fields_ = [
		("Name", c_byte * 32),
		("FileName", c_byte * 60),
		("NandSize", c_uint32),
		("Offset", c_uint32),
		("NandAddr", c_uint32),
		("ImgFSize", c_uint32),
		("OrigFSize", c_uint32),
	]

class RKAF_Header(Structure):
	_pack_ = True
	_fields_ = [
		("Magic", c_byte * 4),
		("ImgLen", c_uint32),
		("Model", c_byte * 34),
		("ID", c_byte * 30),
		("Manufacturer", c_byte * 56),
		("Unk0", c_uint32),
		("Version", c_uint32),
		("FileCount", c_uint32),
		("UpdFiles", UpdFile * 16),
		("Reserved", c_ubyte * 116)
	]

class PARM_File(Structure):
	_pack_ = True
	_fields_ = [
		("Magic", c_byte * 4),
		("FileLen", c_uint32)
		# File
		# CRC
	]

class KRNL_File(Structure):
	_pack_ = True
	_fields_ = [
		("Magic", c_byte * 4),
		("FileLen", c_uint32)
		# File
		# CRC
	]

class AndroidBoot_Header(Structure):
	_pack_ = True
	_fields_ = [
		("Magic", c_byte * 8),
		("KernelSize", c_uint32),
		("KernelAddr", c_uint32),
		("RamdiskSize", c_uint32),
		("RamdiskAddr", c_uint32),
		("SecondFSize", c_uint32),
		("SecondFAddr", c_uint32),
		("TagsAddr", c_uint32),
		("PageSize", c_uint32),
		("Unk0", c_uint32),
		("Unk1", c_uint32),
		("Name", c_byte * 16),
		("CmdLine", c_byte * 512),
		("SHADigest", c_ubyte * 20),
		("Unk2", c_uint32),
		("Unk3", c_uint32),
		("Unk4", c_uint32),
	]

def read_file(filename: str) -> bytes:
	with open(filename, "rb") as f:
		data = f.read()
	return data

def write_file(filename: str, data: (bytes, bytearray)) -> None:
	with open(filename, "wb") as f:
		f.write(data)

def convert_size(size_bytes: int) -> str:
	if size_bytes == 0:
		return "0B"
	size_name = ("B", "KB", "MB", "GB")
	i = int(floor(log(size_bytes, 1024)))
	p = pow(1024, i)
	s = round(size_bytes / p, 2)
	return "%s %s" % (s, size_name[i])

def derive_rom_key(dna: (bytes, bytearray)) -> (bytes, bytearray):
	global ROM_SECRET

	digest = bytearray(MD5.new(dna).digest())
	for i in range(16):
		digest[i] ^= ROM_SECRET[i]
	return digest

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

# classes
class UpdateRequestFile:
	dna = None
	serial = None
	signature = None
	sys_fw_ver = None
	ver_code = None
	pcba_rev = None

	enc_output = None

	def __init__(self, filename: str = REQUEST_FILE) -> None:
		self.reset()
		if isfile(filename):
			self.parse(read_file(filename))
		else:
			self.generate()
			write_file(filename, self.enc_output)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		pass

	def reset(self) -> None:
		self.dna = None
		self.serial = None
		self.signature = None
		self.sys_fw_ver = None
		self.ver_code = None
		self.pcba_rev = None

	def generate(self) -> (bytes, bytearray):
		global REQUEST_PRV_KEY

		self.sys_fw_ver = 512
		self.ver_code = 27
		self.pcba_rev = 2

		self.dna = urandom(16)
		self.serial = hexlify(self.dna).upper()

		iv = urandom(16)

		cipher = AES.new(REQUEST_SECRET, AES.MODE_CBC, iv)
		signer = PKCS1_v1_5.new(REQUEST_PRV_KEY)

		# not sure what the data on the end is but whatever, it works :3
		body = pack("<4s 16s 3I", REQUEST_MAGIC, self.dna, self.sys_fw_ver, self.ver_code, self.pcba_rev)
		self.signature = signer.sign(SHA1.new(body))

		dec_data = body + self.signature
		enc_data = cipher.encrypt(pad(dec_data, AES.block_size))

		self.enc_output = iv + enc_data

	def parse(self, data: (bytes, bytearray)) -> (bytes, bytearray):
		global REQUEST_PRV_KEY

		self.enc_output = data

		iv = data[:16]

		cipher = AES.new(REQUEST_SECRET, AES.MODE_CBC, iv)
		enc_data = data[16:]  # array + signature
		dec_data = unpad(cipher.decrypt(enc_data), AES.block_size)

		body = dec_data[:-REQUEST_PRV_KEY.size_in_bytes()]  # UNIQUE_MAGIC + DNA
		self.signature = dec_data[-REQUEST_PRV_KEY.size_in_bytes():]

		# verify file magic
		assert body[:4] == REQUEST_MAGIC, "Invalid update request magic"

		# verify signature
		verifier = PKCS1_v1_5.new(REQUEST_PRV_KEY)
		assert verifier.verify(SHA1.new(body), self.signature), "Invalid signature"

		(magic, self.dna, self.sys_fw_ver, self.ver_code, self.pcba_rev) = unpack("<4s 16s 3I", body)
		self.serial = hexlify(self.dna)

class UpdateFile:
	name: str
	offset: int
	size_nopad: int
	size_pad: int
	unique: bool
	key: (bytes, bytearray)  # SecretKeySpec
	iv: (bytes, bytearray)  # IvParameterSpec
	signature: (bytes, bytearray)
	valid: bool

	def get_dict(self) -> dict:
		return {
			"name": self.name,
			"offset": self.offset,
			"size_nopad": self.size_nopad,
			"size_pad": self.size_pad,
			"unique": self.unique,
			"key": hexlify(self.key),
			"iv": hexlify(self.iv),
			"signature": hexlify(self.signature)
		}

class RKFW:
	stream = None
	package_build_datetime = None
	boot_build_datetime = None

	def __init__(self, filename: str) -> None:
		self.reset()
		assert isfile(filename), "Specified RKFW image file doesn't exist"
		self.stream = open(filename, "rb")
		self.stream = StreamIO(self.stream)
		self.read_header()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.stream.close()

	def reset(self) -> None:
		self.stream = None
		self.package_build_datetime = None
		self.boot_build_datetime = None

	def read_header(self) -> None:
		global RKFW_Header, RKFW_MAGIC, RKFW_Type

		# read package header
		fw_hdr = self.stream.read_struct(RKFW_Header)

		# make sure it's a valid package
		assert bytes(fw_hdr.Magic) == RKFW_MAGIC, "Invalid RockChip firmware package magic"
		assert fw_hdr.ChipID == RKFW_ChipID.RK3066, "Invalid RockChip ID"
		self.package_build_datetime = datetime(fw_hdr.Year, fw_hdr.Month, fw_hdr.Day, fw_hdr.Hour, fw_hdr.Minute, fw_hdr.Second)

		self.read_boot()

		if RKFW_Type(fw_hdr.Type) == RKFW_Type.RKAF:
			self.read_rkaf()

			self.stream.seek(-36, 2)
			rkaf_crc = self.stream.read_uint32()  # the RKCRC of the image
			rkaf_md5 = unhexlify(self.stream.read(32))  # stored as hex?
		elif RKFW_Type(fw_hdr.Type) == RKFW_Type.UPDATE:
			pass
		else:
			raise Exception("Invalid RKFW type")

	def read_boot(self) -> None:
		global RKFW_BOOT_MAGIC, RKBoot_Header, RKBootFileRec, RKFW_KEY, OUTPUT_DIR

		boot_img_base = self.stream.tell()
		rk_boot_hdr = self.stream.read_struct(RKBoot_Header)

		assert bytes(rk_boot_hdr.Magic) == RKFW_BOOT_MAGIC, "Invalid RockChip boot magic"
		assert rk_boot_hdr.ChipID == RKFW_ChipID.RK3066, "Invalid RockChip ID"
		self.boot_build_datetime = datetime(rk_boot_hdr.Year, rk_boot_hdr.Month, rk_boot_hdr.Day, rk_boot_hdr.Hour, rk_boot_hdr.Minute, rk_boot_hdr.Second)

		total_size = sizeof(RKBoot_Header)
		for i in range(4):  # 4 files
			# read the file record
			file_rec = self.stream.read_struct(RKBootFileRec)
			# store the location of the last record
			temp = self.stream.tell()
			# seek to the file's data
			self.stream.seek(boot_img_base + file_rec.FileOff)
			# increment the total boot file size
			total_size += file_rec.FileSize + sizeof(RKBootFileRec)
			# read the encrypt file data
			file_data_enc = self.stream.read(file_rec.FileSize)
			# seek back to the end of the last record
			self.stream.seek(temp)
			# decrypt the file
			file_data_dec = ARC4.new(RKFW_KEY).decrypt(file_data_enc)
			# write the file to disk
			with open(join(OUTPUT_DIR, "System Update/RKFW", file_rec.FileName), "wb") as f:
				f.write(file_data_dec)
		total_size += 4  # RKFW CRC

		# write the boot image to a file
		self.stream.seek(boot_img_base)
		self.stream.seek(total_size - 4, 1)
		rk_boot_crc = self.stream.read_uint32()

	def read_rkaf(self) -> None:
		global RKAF_Header, OUTPUT_DIR

		rkaf_base = self.stream.tell()
		rkaf_hdr = self.stream.read_struct(RKAF_Header)
		for single in rkaf_hdr.UpdFiles:
			file_name = str(bytes(single.FileName).rstrip(b"\x00"), "utf8")
			if single.ImgFSize > 0:
				self.stream.seek(rkaf_base + single.Offset)
				with open(join(OUTPUT_DIR, "System Update/RKFW", file_name), "wb") as f:
					read_bytes = 0
					while read_bytes < single.OrigFSize:
						read_size = (single.OrigFSize - read_bytes) if (single.OrigFSize - read_bytes) < BUFF_SIZE else BUFF_SIZE
						temp = self.stream.read(read_size)
						f.write(temp)
						read_bytes += len(temp)

class SystemUpdateFile:
	stream = None
	dna_hash: (bytes, bytearray) = None
	update_files: list = []
	verifier: PKCS1_v1_5 = None

	def __init__(self, f, dna: (bytes, bytearray) = None) -> None:
		global UPDATE_PUB_KEY, SYSTEM_SECRET, SHARED_MAGIC

		self.reset()

		self.stream = f

		self.verifier = PKCS1_v1_5.new(UPDATE_PUB_KEY)

		if dna is not None:
			self.dna_hash = MD5.new(dna).digest()

		iv = self.stream.read(16)
		cipher = AES.new(SYSTEM_SECRET, AES.MODE_CBC, iv)

		header_enc = self.stream.read(16)
		header_dec = cipher.decrypt(header_enc)

		with StreamIO(header_dec) as sio:
			magic = sio.read(4)
			version = sio.read_int()
			file_count = sio.read_int()
			sio.seek(4, 1)  # this is unused
			if magic != SHARED_MAGIC:
				raise Exception("Invalid update magic")
			elif version > 1:
				raise Exception("Invalid update version")
			else:
				record_size = ((file_count * 256) + 16) + UPDATE_PUB_KEY.size_in_bytes()
				self.stream.seek(16)
				record_enc = self.stream.read(record_size)
				# re-init
				cipher = AES.new(SYSTEM_SECRET, AES.MODE_CBC, iv)
				record_dec = cipher.decrypt(record_enc)
		with StreamIO(record_dec) as sio:
			magic = sio.read(4)
			assert magic == SHARED_MAGIC, "Invalid update magic"
			signature = record_dec[-UPDATE_PUB_KEY.size_in_bytes():]
			assert self.verifier.verify(SHA1.new(record_dec[:-UPDATE_PUB_KEY.size_in_bytes()]), signature), "Invalid signature"
			sio.seek(16)
			for i in range(file_count):
				file = UpdateFile()
				file.valid = False  # probably not going to check this ever
				file.name = sio.read(80).split(b"\x00")[0].decode("utf8")  # max file name size is 80 bytes
				file.offset = sio.read_int()
				file.size_nopad = sio.read_int()
				file.size_pad = sio.read_int()
				file.unique = sio.read_int() & 1 != 0
				key = bytearray(sio.read(16))
				if file.unique and dna is not None:  # this is only used if it's a console-unique file
					key = strxor(key, self.dna_hash)
				elif file.unique and dna is None:
					raise Exception("DNA must be provided to decrypt an app update")
				file.key = key
				file.iv = sio.read(16)
				file.signature = sio.read(UPDATE_PUB_KEY.size_in_bytes())
				self.update_files.append(file)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.stream.close()

	def reset(self) -> None:
		self.stream = None
		self.dna_hash = None
		self.h = None
		self.update_files = []
		self.verifier = None

	def list_files(self) -> None:
		#if DEBUG:
		print(">>> " + self.stream.name)
		for single in self.update_files:
			print("+ %s @ %s, %s (%s unpadded)" % (single.name, hex(single.offset), convert_size(single.size_pad), convert_size(single.size_nopad)))

	def extract_files(self, directory: str = OUTPUT_DIR) -> None:
		global DEBUG

		for single in self.update_files:
			self.stream.seek(single.offset)
			cipher = AES.new(single.key, AES.MODE_CBC, single.iv)
			hasher = SHA1.new()
			bz2 = BZ2Decompressor()
			read = 0
			with open(join(directory, single.name), "wb") as f:
				while read < single.size_pad:
					# calculate the exact size of the read
					amt = (single.size_pad - read) if (single.size_pad - read) < BLOCK_SIZE else BLOCK_SIZE
					enc_buff = self.stream.read(amt)
					# decrypt the buffer
					dec_buff = cipher.decrypt(enc_buff)
					# remove padding
					if len(dec_buff) < BLOCK_SIZE:
						if single.size_nopad < single.size_pad:
							diff = single.size_pad - single.size_nopad
							dec_buff = dec_buff[:-diff]
					# update the hasher
					hasher.update(dec_buff)
					# decompress if bz2
					if single.name.endswith(".bz2"):
						dec_buff = bz2.decompress(dec_buff)
					# output to file
					f.write(dec_buff)
					read += len(enc_buff)
				assert self.verifier.verify(hasher, single.signature), "Invalid signature"
			# rename the .bz2 files because they're already decompressed
			if single.name.endswith(".bz2"):  # .tar.bz2 files
				if DEBUG:
					print("> Unpacking %s..." % (single.name))
				orig_path = join(directory, single.name)
				new_path = join(directory, single.name.replace(".bz2", ".tar"))
				if isfile(new_path):
					remove(new_path)
				rename(orig_path, new_path)
				if DEBUG:
					print("> Renamed %s to %s" % (basename(orig_path), basename(new_path)))
				with TarFile(new_path) as tar_f:
					if DEBUG:
						for member in tar_f.getmembers():
							print("+ %s @ %s, %s" % (member.name, hex(member.offset), convert_size(member.size)))
					tar_f.extractall(directory)
				remove(new_path)
				if DEBUG:
					print("- Deleted %s" % (single.name))
			elif single.name.endswith(".img"):  # rk30 images
				if DEBUG:
					print("> Unpacking %s..." % (single.name))
				RKFW(join(directory, single.name))

def main() -> None:
	global UPDATE_PUB_KEY, REQUEST_PRV_KEY, UPDATE_PUB_KEY_FILE, REQUEST_PRV_KEY_FILE, REQUEST_FILE, APP_UPDATE_FILE, SYS_UPDATE_FILE

	UPDATE_PUB_KEY = RSA.import_key(read_file(join("Keys", UPDATE_PUB_KEY_FILE)))
	REQUEST_PRV_KEY = RSA.import_key(read_file(join("Keys", REQUEST_PRV_KEY_FILE)))

	upd_req = UpdateRequestFile(join("Research", REQUEST_FILE))
	print("Serial #:          " + upd_req.serial)
	print("System FW Version: " + str(upd_req.sys_fw_ver))
	print("Version Code:      " + str(upd_req.ver_code))
	print("PCBA Revision:     " + str(upd_req.pcba_rev))

	if isfile(join("Updates/System", SYS_UPDATE_FILE)):
		print()
		with open(join("Updates/System", SYS_UPDATE_FILE), "rb") as f:
			sys_upd = SystemUpdateFile(f)
			sys_upd.list_files()
			sys_upd.extract_files("Output/System Update")

	if isfile(join("Updates/App", APP_UPDATE_FILE)):
		print()
		with open(join("Updates/App", APP_UPDATE_FILE), "rb") as f:
			app_upd = SystemUpdateFile(f, upd_req.dna)
			app_upd.list_files()
			app_upd.extract_files("Output/App Update")

if __name__ == "__main__":
	main()