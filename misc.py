import socket
import struct
import pubcrypt
import random
import timeit
import threading
import os
import hashlib
import time

class SymCrypt:
	def __init__(self, key):
		self.key = key
	def __both(self, data):
		di = 0
		ki = 0
		key = self.key
		out = []
		while di < len(data):
			out.append(data[di] ^ key[ki])
			di = di + 1
			ki = len(key) % (ki + 1)
		return bytes(out)
	def crypt(self, data):
		return self.__both(data)
	def decrypt(self, data):
		return self.__both(data)
	
class PktCodeClient:
	GetPublicKey 		= 0
	SetupEncryption		= 1
	EncryptedMessage	= 2
	BlockConnect		= 3
	Write				= 4
	Read				= 5
	Exchange8			= 6
	BlockLock			= 7
	BlockUnlock			= 8
	BlockSize			= 9
	WriteAddLoop		= 10
	WriteHold		 	= 11
	DoWriteHold			= 12
	GetWriteHoldCount	= 13
	FlushWriteHold	 	= 14
	Ack					= 15
		
class PktCodeServer:
	PublicKey			= 0
	EstablishLink		= 1
	EstablishLinkFail	= 2		# TODO: implement
	EncryptedMessage	= 3
	BlockConnectFailure	= 4
	BlockConnectSuccess	= 5
	NoLink				= 6
	WriteSuccess		= 7
	ReadSuccess			= 8
	Exchange8Success	= 9
	OperationFailure	= 10
	UnlockSuccess		= 11
	UnlockFailed		= 12
	LockFailedOverlap	= 13
	LockFailedMax		= 14
	LockSuccess			= 15
	BlockSizeReply		= 16
	GetWriteHoldCount 	= 17
	FlushWriteHold		= 18
	
class IDGen:
	def __init__(self, size):
		self.size = size
		self.gened = {}
	'''
		Generates a unique ID (could have been used before)
	'''
	def gen(size):
		o = []
		x = 0
		while x < size:
			o.append(random.randint(0, 255))
			x = x + 1
		return bytes(o)
	'''
		Generates a unique (not used before) ID
	'''
	def ugen(self):
		while True:
			uid = IDGen.gen(self.size)
			if uid not in self.gened:
				self.gened[uid] = True
				return uid

class VectorManEntry:
	def __init__(self, begin, end):
		self.begin = begin
		self.end = end
				
class VectorMan:
	def __init__(self):
		self.high = 100
		self.irange = []
		
	def IsVectorGood(self, vector):
		irange = self.irange
		for ir in irange:
			if vector >= ir.begin and vector <= ir.end:
				print('used vector:%s' % vector)
				return False
		return True
	'''
		this function needs improvement so that we are not
		storing every single vector, but instead store some
		as a range to decrease memory usage, and search time
		when checking if vector is in list
		
		BUT, this is okay for now for testing...
		
		TODO: improve this situation
	'''
	def MarkVectorUsed(self, vector):
		irange = self.irange
		# find range we can append onto
		_ir = None
		for ir in irange:
			if vector + 1 == ir.begin:
				ir.begin = ir.begin - 1
				_ir = ir
				break
			if vector - 1 == ir.end:
				ir.end = ir.end + 1
				_ir = ir
				break
		
		# try to combine range we just added to with another
		if _ir is not None:
			for ir in irange:
				if _ir.end + 1 == ir.begin:
					ir.begin = _ir.begin
					irange.remove(ir)
					break
				if _ir.begin - 1 == ir.end:
					ir.end = _ir.end
					irange.remove(ir)
					break
		else:
			irange.append(VectorManEntry(vector, vector))
	
	def IsRangeTooMany(self, max):
		if len(self.irange) > max:
			return True
		return False
	
	def GetNewVector(self):
		vector = self.high
		self.high = vector + 1
		return vector
				
def BuildEncryptedMessage(link, data):
	crypter = link['crypter']
	vman = link['vman']
	ulid = link['ulid']
	
	# add vector and data (to be hashed)
	_vector = vman.GetNewVector()
	vector = struct.pack('>Q', _vector)
	data = vector + data
	
	# hash vector and data
	m = hashlib.sha512()
	m.update(data)
	hash = m.digest()
	#hash = bytearray(64)
	
	# encrypt data (but not ulid and type code)
	data = hash + data
	
	data = crypter.crypt(data)
	
	# add together to make final packet form
	data = struct.pack('>B', PktCodeClient.EncryptedMessage) + ulid + data
	
	# return final form
	return (data, _vector)
				
def ProcessRawSocketMessage(link, data):	
	# if not encrypted then just return message whole
	if data[0] != PktCodeClient.EncryptedMessage:
		return (False, data, None)
	
	crypter = link['crypter']
	vman = link['vman']
	ulid = link['ulid']
	
	# it is encrypted so we need to decrypt and verify it
	data = data[1:]
	# get unique link id
	_ulid = data[0:4]
	if _ulid != ulid:
		# apparently, not meant for us..
		return (None, data, None)
	data = data[4:]
	
	# decrypt remaining message
	data = crypter.decrypt(data)
	
	# get hash
	hash = data[0:64]
	# hash remaining data so we can verify hash
	data = data[64:]
	
	m = hashlib.sha512()
	m.update(data)
	_hash = m.digest()
	if _hash != hash:
		# failed hash verification (ignore it)
		return (False, data)
	# verify vector is valid
	vector = struct.unpack_from('>Q', data)[0]
	# return the actual data (which has now been decrypted and verified)
	return (True, data[8:], vector)