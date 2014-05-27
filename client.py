import socket
import struct
import pubcrypt
import random
import timeit
import threading
import os
import sys
import hashlib
import time
import math

from misc import *

class OperationException(Exception):
	pass
class LockingException(Exception):
	pass
class CommunicationException(Exception):
	pass
class WriteHoldCountException(Exception):
	pass
	
'''
	This will create a client object and provide access to the remote block.
'''
class Client():
	def __init__(self, rip, rport, bid):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		
		rip = socket.gethostbyname(rip)
		#rip = socket.inet_aton(rip)
		#print(type(rip))
		#exit()
		sock.bind(('0.0.0.0', 0))
		self.saddr = (rip, rport)
		sock.connect(self.saddr)		
		
		self.sock = sock
		self.link = {
			'vman':		VectorMan()
		}
		self.bid = bid
		self.pubkey = None
		self.linkvalid = False
		self.outgoing = {}
		self.vexecuted = {}
		self.nid = 100

		# these help with determining if the link
		# is no longer working and we need to try
		# to re-establish it
		self.lmst = 0			# last message send time
		self.lmt = 0			# last message (recieved) time
		
		self.cache = {}
		self.cache_dirty = []
		self.cache_lastread = {}
		self.cache_lastwrite = {}
		self.cache_maxpages = 128
		
		self.wholds = []
		
		self.x = 0				# debugging variable (safe to remove)
		
		self.vexecwarnlimit = 1024
		
	'''
		If blocking:
			Will return True for success, or raise Exception.
		If non-blocking:
			Will return None
	'''
	
	def GetWriteHoldCount(self):
		self.DoBlockingLinkSetup()

		_data = struct.pack('>B', PktCodeClient.GetWriteHoldCount)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		ret = self.HandlePackets(getvector = vector)
		if ret is None:
			raise OperationException()
		
		return ret
		
	def CacheTick(self):
		if len(self.cache) > self.cache_maxpages:
			# drop the oldest page
			oldpage = None
			oldtime = time.time()
			for page in self.cache_lastread:
				ptime = self.cache_lastread[page]
				if ptime < oldtime:
					oldtime = ptime
					oldpage = page
			for page in self.cache_lastwrite:
				ptime = self.cache_lastwrite[page]
				if ptime < oldtime:
					oldtime = ptime
					oldpage = page
			# flush out page back to server
			# drop old page
			print('commiting and dropping cache page %x' % page)
			del self.cache[oldpage]
			if oldpage in self.cache_lastread:
				del self.cache_lastread[oldpage]
			if oldpage in self.cache_lastwrite:
				del self.cache_lastwrite[oldpage]
		
	def CacheRead(self, offset, length):
		cache = self.cache
		# align to page boundary
		page = offset & ~0x3ff
		# break offset down into local page offset
		loffset = offset - page
		dleft = length
		
		ct = time.time()
		
		out = []
		while dleft > 0:
			if page not in cache:
				self.CacheTick()
				cache[page] = self.Read(page, 1024, block = True, cache = False)
				#print('[read] cache page:%x' % (page))
			self.cache_lastread[page] = ct
			# either a partial read or a full read
			#print('		dleft:%x loffset:%x' % (dleft, loffset))
			if dleft > (1024 - loffset):
				lsize = 1024 - loffset
			else:
				lsize = dleft
			
			#print('cache read offset:%x loffset:%x lsize:%x' % (offset, loffset, lsize))
			
			out.append(cache[page][loffset:loffset + lsize])
		
			# subtract just what we read
			dleft = dleft - lsize
			
			# prepare page and loffset
			loffset = (loffset + lsize) & 0x3ff
			# goto next page
			page = page + 0x400
		
		out = b''.join(out)
		#print(len(out), length)
		assert(len(out) == length)
		return out
	
	def CacheWrite(self, offset, data):
		cache = self.cache
		
		page = offset & ~0x3ff
		loffset = offset - page
		dleft = len(data)
		
		ct = time.time()
		
		while dleft > 0:
			#print('[write] cache loffset:%x page:%x dleft:%x' % (loffset, page, dleft))
			if page not in cache:
				self.CacheTick()
				cache[page] = self.Read(page, 1024, block = True, cache = False)
				#print('[write] cached page:%x' % page)
			self.cache_dirty.append(page)
			self.cache_lastwrite[page] = ct
			#print('done')
			
			# either a partial write or full write
			if dleft > 1024 - loffset:
				lsize = 1024 - loffset
			else:
				lsize = dleft
				
			#print('cache write offset:%x loffset:%x lsize:%s' % (offset, loffset, lsize))
			
			# this looks ugly but how else can i do it quickly
			cache[page] = cache[page][0:loffset] + data[len(data) - dleft:lsize] + cache[page][loffset + lsize:]
			
			# subtract what we wrote
			dleft = dleft - lsize
			# parepare next page and loffset
			loffset = (loffset + lsize) & 0x3ff
			page = page + 0x400
		
	def FlushWriteHold(self):
		_data = struct.pack('>B', PktCodeClient.FlushWriteHold)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		ret = self.HandlePackets(getvector = vector)
		if ret is None:
			raise OperationException()
		
		return ret

	def DoWriteHold(self, block = False, discard = True, verify = False, ticknet = False):
		self.DoBlockingLinkSetup()

		# verify will ensure the writes are all there
		# by checking the count and if not correct updatin
		# the flushing then updating the writes
		if verify:
			tryagain = True
			while tryagain:
				# get server count of writes on hold to verify they are all there
				scnt = self.GetWriteHoldCount()
				# are all the writes there?
				if len(self.wholds) != scnt:
					# flush the ones there if any
					self.FlushWriteHold()
					# try to re-send them
					for hold in self.wholds:
						# send the write hold
						self.WriteHold(hold[0], hold[1])
					# re-check they are all there
					# (loop again)
				else:
					# exit the loop
					tryagain = False
		
		_data = struct.pack('>B', PktCodeClient.DoWriteHold)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)

		# flush the write holds on our side
		self.wholds = []
		
		if discard is False and block is False:
			# discard the write reply when it arrives
			self.vexecuted[vector] = True

		#if discard is False and block is False:
		#	print('warning')
			
		if block is False and ticknet is False:
			return None
		
		if block is False:
			vector = None
		# block for this specific vector
		ret = self.HandlePackets(getvector = vector)
		

		
		if block and ret is None:
			raise OperationException()
		return ret
		
	def WriteHold(self, offset, data, block = False, discard = True, ticknet = False, wt = True):
		self.wholds.append((offset, data))
		
		return self.Write(offset, data, block = block, hold = True, discard = discard, ticknet = ticknet, wt = wt)
	
	def Write(self, offset, data, block = False, hold = False, discard = True, cache = True, wt = True, ticknet = False):
		self.DoBlockingLinkSetup()
		
		if hold:
			code = PktCodeClient.WriteHold
		else:
			code = PktCodeClient.Write
	
		# serves mainly to allow reads from cache to work properly
		# you can still block or not block on your writes
		if cache:
			self.CacheWrite(offset, data)
			# if write-through not set then just return (only write to cache)
			if wt is False:
				return
		
		_data = struct.pack('>BQ', code, offset) + data
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		#print('sent write')
		
		# does not make sense to discard and block (will just fil up vexecuted)
		if discard is False and block is False:
			# discard the write reply when it arrives
			self.vexecuted[vector] = True

		#if discard is False and block is False:
		#	print('warning')
			
		if block is False and ticknet is False:
			return None
			
		if block is False:
			vector = None
			
		# block for this specific vector
		ret = self.HandlePackets(getvector = vector)
		if block and ret is None:
			raise OperationException()
		return ret
		
	def WriteAddLoop(self, offset, jump, count, data, block = True, discard = True, ticknet = False):
		self.DoBlockingLinkSetup()
			
		_data = struct.pack('>BQQQ', PktCodeClient.WriteAddLoop, offset, jump, count) + data
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)

		if discard is False and block is False:
			# discard the write reply when it arrives
			self.vexecuted[vector] = True
			
		if block is False and ticknet is False:
			return
		
		if block is False:
			vector = None
		# block for this specific vector
		ret = self.HandlePackets(getvector = vector)
		if block and ret is None:
			raise OperationException()
		return ret
		
	'''
		If blocking:
			Will return bytes or raise Exception for failure.
		If non-blocking:
			Will return None
	'''
	def Read(self, offset, length, block = True, cache = True, ticknet = False, discard = True):
		self.DoBlockingLinkSetup()
		
		# it does not make sense to do non-blocking I/O when you
		# have a cache you can use, so lets use the cache
		if cache:
			ret = self.CacheRead(offset, length)
			if ret is not None:
				return ret
		
		_data = struct.pack('>BQH', PktCodeClient.Read, offset, length)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if discard is False and block is False:
			# discard the write reply when it arrives
			self.vexecuted[vector] = True
			
		if block is False and tickned is False:
			return
		
		if block is False:
			vector = None
			
		ret = self.HandlePackets(getvector = vector)
		if block and ret is None:
			raise OperationException()
		return ret
		
	def Lock(self, offset, data, block = True):
		_data = struct.pack('>BQ', PktCodeClient.BlockLock, offset) + data
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.cryper, _data)
		
		if block is False:
			vector = None
		ret = self.HandlePackets(getvector = vector)
		if block and ret is False:
			raise OperationException()
		return ret
		
	def Unlock(self, offset, block = True):
		_data = struct.pack('>BQ', PktCodeClient.BlockUnlock, offset)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if block is False:
			vector = None
		ret = self.HandlePackets(getvector = vector)
		if block and ret is False:
			raise OperationException()
		return ret
		
	def GetBlockSize(self, block = True):
		
		_data = struct.pack('>B', PktCodeClient.BlockSize)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if block is False:
			vector = None
		ret = self.HandlePackets(getvector = vector)
		if block and ret is False:
			raise OperationException()
		return ret
		
	def DoBlockingLinkSetup(self):
		ts = time.time()
		while self.linkvalid is False:
			# try to setup link
			print('getting public key')
			self.GetPublicKey()
			st = time.time()
			while self.linkvalid is False:
				self.HandlePackets()
				# if too much time passes, abort and try again
				if time.time() - st > 15:
					break
				time.sleep(0)
				# check if we have been trying for way too long
				# because the main application might want to do
				# other things, or even release any file locks
				# that it holds
				if time.time() - ts > (60 * 15):
					raise CommunicationException()
	def GetOutstandingCount(self):
		return len(self.outgoing)
	def SetVectorExecutedWarningLimit(self, limit):
		self.vexecwarnlimit = limit
	def GetVectorExecutedWarningLimit(self):
		return self.vexecwarnlimit
	def HandlePackets(self, getvector = None):
		ter = time.time()
		
		if len(self.vexecuted) > self.vexecwarnlimit:
			print('WARNING: executed vectors (for non-blocking I/O) are above limit:%s/%s' % (len(self.vexecuted), self.vexecwarnlimit))
		
		# read as many packets as we can
		while True:
			ct = time.time()
			# 1. send any outgoing packets not sent
			# 2. resend any packets we have not heard a reply about
			# 3. remove any packets we have heard a reply about
			outgoing = self.outgoing
			toremove = []
			toadd = []
			
			for vector in outgoing:
				out = self.outgoing[vector]
				# vector, last-time-sent, data
				#if out[0] in self.vexecuted:
					# okay we have got a reply for it so remove it
					# from the outgoing list, and hopefully someone
					# grabs it from the vector executed list later
				#	continue
				'''
					This can be a bit confusing. Basically, what
					happens is a packet is first added to the outgoing
					so this does not always resend a packet, but also
					sends the very first packet. So do not think all
					packets being sent here are re-sends because most
					are going to be first-time sends.
				'''
				
				# for network latency testing
				#if out[1] == 0:
					# delay the packet by 100ms (simulates 50ms to server and 50ms back)
				#	outgoing[out[0]] = (out[0], (ct - 5) + 0.1, out[2], out[3], out[4])
				#	out = outgoing[out[0]]
				
				if ct - out[1] > 5:
					if out[1] > 0:
						#print('resend vector:%s' % vector)
						pass
					# it has been too long so resend it
					if self.crypter != out[3]:
						raise Exception('DEBUG')
						# re-encrypt the data
						data, vector = BuildEncryptedMessage(self.link, out[4])
						#outgoing[vector] = (vector, out[1], data, self.crypter, data[4])
						toadd.append((vector, out[1], data, self.crypter, out[4]))
						# schedule the old vector to be removed
						toremove.append(out[0])
						# do not send old vector, just skip it
						print('re-encrypted old-vector:%s new-vector:%s' % (out[0], vector))
						# if we were waiting for this packet then we need to
						# reset it to the new vector numeral
						if out[0] == getvector:
							getvector = vector
						continue
					try:
						self.sock.send(out[2])
					except Exception as e:
						print('WARNING: socket exception')
						print(e)
						continue
					# update time last sent
					outgoing[out[0]] = (out[0], ct, out[2], out[3], out[4])
					# record the last time we sent a message
					self.lmst = ct
					continue
			# remove any old (old encryption) outgoing packets and
			# this had to be done outside the iteration loop because
			# dicts do not like when you change them during iteration
			for tr in toremove:
				del outgoing[tr]
			# add any newly encrypted packets back into outgoing
			# i had to do this outside the iteration loop because
			# dicts do not like when you change them during iteration
			for ta in toadd:
				outgoing[ta[0]] = ta
			
			# try to re-establish our link, this will not flush
			# our outgoing list so everything should pick back
			# up as normal
			if self.lmt > 0 and self.lmst - self.lmt > (60 * 5):
				# okay, lets consider our link dead
				# and try to restablish it
				self.linkvalid = False
				self.DoBlockingLinkSetup()
			
			# wait just a bit because if zero we just burn CPU
			# doing a polling loop and that actually decreases
			# the performance
			if getvector is None:
				# if we are not waiting for anything just do a quick
				# check for packets 
				self.sock.settimeout(0)
			else:
				# if we are waiting for something we might want to
				# slow down a bit by waiting longer
				self.sock.settimeout(0.1)
			while True:
				try:
					data, addr = self.sock.recvfrom(0xffff)
					# record last time we recieved a message
					self.lmt = time.time()		
				except Exception as e:
					break
				encrypted, data, svector = ProcessRawSocketMessage(self.link, data)

				# let the server know we got the packet
				if encrypted is None:
					# packet was bad, encrypted is None because we have no
					# idea if it is encrypted or not
					continue
				
				if encrypted is True:
					# we dont use vectors for acks because they may
					# get lost and we do not track them so vectors
					# would get lost and fill up the server's vector
					# ranges making the connection unusable
					_data, _tmp = BuildEncryptedMessage(self.link, struct.pack('>BQ', PktCodeClient.Ack, svector), vector = 0)
					self.sock.send(_data)
									
				if encrypted is False or self.link['vman'].IsVectorGood(svector) is True:
					# continue processing packet
					ret, vector, match = self.HandlePacket(data, getvector = getvector)
					if match is None:
						# unknown packet
						continue
					
					# remove vector from outgoing (blocking or non-blocking)
					if vector is not None:
						# had this happen, not sure
						if vector in self.outgoing:
							del self.outgoing[vector]
							#print('removing vector:%s' % vector)
					
					if match is True:
						# blocking call
						return ret
					else:
						# non-blocking call (stores result)
						if vector is not None:
							# if a vector entry has been made then it signifies
							# that we wish to keep the result/reply, otherwise we
							# just throw the result/reply away
							if vector in self.vexecuted:
								# do not discard results, but store them
								print('added to vexecuted for vector:%s' % vector)
								#print(ret)
								#raise Exception('LOL')
								self.vexecuted[vector] = ret
					# end-of-is-match-if-statement
				# end-of-is-vector-good-if-statement
			# end-of-packet-read-loop
			
			# the only way we leave this function is if
			# we have a reply on a blocking call, so if
			# vector is None then this call is non-blocking
			# and we can gracefully exit, if not just keep
			# going
			# TODO: implement a timeout
			if getvector is None:
				break
		return
	
	def HandlePacket(self, data, getvector = None):
		type = data[0]
		data = data[1:]
		if 		type == PktCodeServer.PublicKey:
			print('got public key')
			# we got public key, now setup the encryption
			nid = struct.unpack_from('>I', data)[0]
			if nid == self.nid:
				self.pubkey = pubcrypt.toi256(data[4:])
				print('setup encryption')
				self.SetupEncryption()
		elif 	type == PktCodeServer.EstablishLink:
			# we have established a link
			print('established link')
			nid = struct.unpack_from('>I', data)[0]
			if nid == self.nid:
				data = data[4:]
				self.link['ulid'] = data
				self.ConnectBlock(self.bid)
		elif	type == PktCodeServer.BlockConnectFailure:
			nid = struct.unpack_from('>I', data)[0]
			if nid == self.nid:
				raise Exception('Failure Connecting To Block')
		elif	type == PktCodeServer.NoLink:
			self.linkvalid = False
			print('no link so doing reconnect')
			self.DoBlockingLinkSetup()
		elif 	type == PktCodeServer.BlockConnectSuccess:
			print('block connected')
			self.linkvalid = True
		elif	type == PktCodeServer.FlushWriteHold:
				vector = struct.unpack_from('>Q', data)[0]
				if vector == getvector:
					return (True, vector, True)
				return (True, vector, False)
		elif	type == PktCodeServer.GetWriteHoldCount:
				vector, count = struct.unpack_from('>QQ', data)
				if vector == getvector:
					return (count, vector, True)
				return (count, vector, False)
		elif	type == PktCodeServer.WriteSuccess:
				vector, offset, length = struct.unpack_from('>QQH', data)
				if vector == getvector:
					return (True, vector, True)
				return (True, vector, False)
		elif	type == PktCodeServer.ReadSuccess:
				vector, offset, length = struct.unpack_from('>QQH', data)
				data = data[18:]
				if vector == getvector:
					return (data, vector, True)
				return (data, vector, False)
		elif	type == PktCodeServer.OperationFailure:
				vector = struct.unpack_from('>Q', data)[0]
				if vector == getvector:
					return (None, vector, True)
				return (None, vector, False)
		elif	type == PktCodeServer.Exchange8Success:
				vector, offset, oldval = struct.unpack_from('>QQB', data)
				if vector == getvector:
					return (oldval, vector, True)
				return (oldval, vector, False)
		elif	type == PktCodeServer.LockFailedOverlap:
				vector, offset, length = struct.unpack_from('>QQQ', data)
				if vector == getvector:
					return (False, vector, True)
				return (False, vector, False)
		elif	type == PktCodeServer.LockFailedMax:
				vector, offset, length = struct.unpack_from('>QQQ', data)
				if vector == getvector:
					return (False, vector, True)
				return (False, vector, False)
		elif	type == PktCodeServer.LockSuccess:
				vector, offset, length = struct.unpack_from('>QQQ', data)
				if vector == getvector:
					return (True, vector, True)
				return (True, vector, False)
		elif	type == PktCodeServer.UnlockFailed:
				vector, offset, force = struct.unpack_from('>QQB', data)
				if vector == getvector:
					return (False, vector, True)
				return (False, vector, False)
		elif	type == PktCodeServer.UnlockSuccess:
				vector, offset, force = struct.unpack_from('>QQB', data)
				if vector == getvector:
					return (True, vector, True)
				return (True, vector, False)
		elif	type == PktCodeServer.BlockSizeReply:
				vector, size = struct.unpack_from('>QQ', data)
				if vector == getvector:
					return (size, vector, True)
				return (size, vector, False)
		return (None, None, None)
	
	def GetPublicKey(self):
		data = struct.pack('>BI', PktCodeClient.GetPublicKey, self.nid)
		self.sock.send(data)

	def SetupEncryption(self):
		key = IDGen.gen(7)
		self.link['crypter'] = SymCrypt(key)
		crypter = self.link['crypter']
		self.crypter = crypter
		# encrypt key with public key
		key = pubcrypt.crypt(key, self.pubkey)
		data = struct.pack('>BI', PktCodeClient.SetupEncryption, self.nid) + key
		self.sock.send(data)
				
	def ConnectBlock(self, bid):
		sock = self.sock
		_data = struct.pack('>BI', PktCodeClient.BlockConnect, self.nid) + bid
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
class ChunkSystem(Client):
	ChunkFree 		= 1
	ChunkBegin		= 2
	ChunkData		= 3

	def __init__(self, sip, sport, bid):
		Client.__init__(self, sip, sport, bid)
	def Format(self, force = False, csize = 4096):
		sig = self.Read(0, 8)
		# check if already contains a file system
		if sig != bytes((0, 0, 0, 0, 0, 0, 0, 0)) and force is False:
			return False
		# lets clear the signature field
		self.Write(0, bytes((0, 0, 0, 0, 0, 0, 0, 0)))
		# get block size
		bsz = self.GetBlockSize()
		
		# B=status Q=size
		# 000 - whole
		# 001 - split 
		# 002 - fully used (not fully used)
		
		# for 1GB there are 19 levels (0-18)
		levels = 28
		self.levels = levels
		
		self.base = 4096
		self.bucketmaxslots = int((self.base - 10) / 8)
		
		print('max storage size:%s' % ((4096 << (levels - 1)) * 510))
		
		#levelsize = 4096 << level
		
		# reserve 4096 bytes for the initial level stack for each and 4096 bytes for the master area
		doffset = 4096 * levels + 4096
		self.doffset = doffset
		
		# save this in the header
		self.Write(100, struct.pack('>IQQ', levels, doffset, self.base))
		
		# max 510 entries per bucket
		for levelndx in range(0, levels):
			# [next][top]
			self.Write(levelndx * 4096 + 4096, struct.pack('>QH', 0, 0))
			self.Write(200 + levelndx * 8, struct.pack('>Q', levelndx * 4096 + 4096))
		
		# work down creating the largest possible chunks
		# while placing the chunks into their respective
		# buckets; i am starting with 1GB so that makes
		# the maximum memory that i can manage 510GB, if
		# i start with a larger size (more levels) or increase
		# the smallest level i can handle larger blocks
		fsz = 4096 << (levels - 1)
		_bsz = bsz
		clevel = levels - 1
		cmoff = doffset
		# make sure we do not go smaller than 4096 and that
		# we have at least 4096 bytes left.. we just discard
		# any extra at the end below 4096
		while fsz >= 4096 and _bsz >= 4096:
			# calculate whole chunks
			wgb = int(_bsz / fsz)
			# calculate remaining bytes
			_bsz = _bsz - (wgb * fsz)
			print('level:%s got %x count of %x size chunks with %x remaining' % (clevel, wgb, fsz, _bsz))
			# place chunks into bucket
			boff = 4096 + clevel * 4096
			# make sure we do not exceed the bucket's current limit; this
			# is likely to happen if we use too small of our largest buckets
			# size compared with the block size.. for example if our largest
			# bucket is 1GB and we have 512GB then we are likely going to
			# exceed 510 entries thus overfilling our boot strapping buckets
			assert(wgb <= 510)
			
			self.Write(boff, struct.pack('>QH', 0, wgb))
			
			for i in range(0, wgb):
				self.Write(boff + (8 + 2) + i * 8, struct.pack('>Q',  cmoff))
				print('cmoff:%x' % cmoff)
				# track our current data position in the block
				cmoff = cmoff + fsz
			# decrease chunk size
			fsz = fsz >> 1
			clevel = clevel - 1
		return

	def TestSegmentAllocationAndFree(self):
		tpb = 0
		tpbc = 0
		lsz = 0
		
		self.SetVectorExecutedWarningLimit(2048)		
		segments = []
		while True:
			# let the network do anything it needs to do
			if self.GetOutstandingCount() >= 100:
				while self.GetOutstandingCount() >= 100:
					self.HandlePackets()
		
			sz = random.randint(1, 1024 * 1024 * 100)
			
			st = time.time()
			chunks = self.AllocChunksForSegment(sz)
			tt = time.time() - st
			
			tpb = tpb + (tt / (sz / 1024 / 1024 / 1024))
			tpbc = tpbc + 1
			
			print('average time per GB is %s and largest alloc is:%s' % (tpb / tpbc, lsz))
			
			#print(chunks)
			
			if chunks is None:
				# free something
				print('freeing segment')
				if len(segments) < 1:
					continue
				#exit()
				i = random.randint(0, len(segments) - 1)
				for chunk in segments[i]:
					self.PushChunk(chunk[2], chunk[0])
				
				del segments[i]
				# try to allocate again, and if fails
				# then we will free another
				continue
			if sz > lsz:
				lsz = sz
			
			# make sure no overlap
			for chunk in chunks:
				for segment in segments:
					for _chunk in segment:
						s = chunk[0]
						_s = _chunk[0]
						e = (chunk[0] + chunk[1]) - 1
						_e = (_chunk[0] + _chunk[1]) - 1
						if (s >= _s and e <= _e) or (_s >= s and _e <= e) or \
						   (s >= _s and s <= _e) or (e >= _s and e <= _e):
							print('OVERLAP')
							print('start:%x end:%x length:%x level:%s' % (s, e, chunk[1], chunk[2]))
							print('start:%x end:%x length:%x level:%s' % (_s, _e, _chunk[1], _chunk[2]))
							exit()	
			segments.append(chunks)
		
		while True:
			self.HandlePackets()
		return
		
	
	def AllocChunksForSegment(self, seglength):
		chunks = []
		if self.__AllocChunksForSegment(seglength, self.levels - 1, chunks) is False:
			# push all the chunks we did get back..
			for chunk in chunks:
				# push chunk back into specified level
				self.PushChunk(chunk[2], chunk[0])
			return None
		# we should have enough chunks for the segment
		return chunks
		
	def __AllocChunksForSegment(self, seglength, level, chunks):
		if level < 0:
			#print('level bottomed out')
			return False
		# see if this size chunk will fit it
		lchunksz = self.base << level
		# if level is 0 then we will just have to have some waste because
		# there is no real way around it
		if lchunksz > seglength and level > 0:
			# too large, so try a lower level
			#print('level:%s is too large (lchunksz:%x seglength:%x) so going lower' % (level, lchunksz, seglength))
			return self.__AllocChunksForSegment(seglength, level - 1, chunks)
		# how many can fit into it?
		cnt = int(seglength / lchunksz)
		if level == 0 and (cnt * lchunksz < seglength):
			# we are into base pages so we are going to have to just make
			# it work by partially using another page
			cnt = cnt + 1
		# try to allocate them
		for x in range(0, cnt):
			chunk = self.PullChunk(level)
			if chunk is None:
				#print('none left in level:%s so going lower' % level)
				# no chunks left, try lower level
				return self.__AllocChunksForSegment(seglength, level - 1, chunks)
			#print('used chunk on level:%s' % level)
			chunks.append((chunk, lchunksz, level))
			seglength = seglength - lchunksz
			if seglength < 1:
				return True
		# if we still have some left, try the next lower level
		return self.__AllocChunksForSegment(seglength, level - 1, chunks)
	
	def PushBasePages(self, pages):
		for page in pages:
			self.PushBasePage(page)
		return True
	
	def PushBasePage(self, page):
		level = 0
		boff = struct.unpack('>Q', self.Read(200 + level * 8, 8))[0]
		next, top = struct.unpack('>QH', self.Read(boff, 10))
		if top == self.bucketmaxslots:
			# create new bucket from one of the pages
			self.WriteHold(page, struct.pack('>QH', boff, 0))
			self.WriteHold(200 + level * 8, struct.pack('>Q', page))
			self.DoWriteHold()
			return True
		# push a page into the bucket
		self.WriteHold(boff + 10 + top * 8, struct.pack('>Q', page))
		self.WriteHold(boff, struct.pack('>QH', next, top + 1))
		self.DoWriteHold()
		return True
		
	def PushChunk(self, level, chunk):
		# short-circuit to the specialized function for pages (not chunks)
		#print('push-chunk level:%s chunk:%x' % (level, chunk))
		if level == 0:
			return self.PushBasePage(chunk)
		boff = struct.unpack('>Q', self.Read(200 + level * 8, 8))[0]
		next, top = struct.unpack('>QH', self.Read(boff, 10))
		if top == self.bucketmaxslots:
			# create new bucket from ... a page (base page / base chunk)
			page = self.PullChunk(0)
			if page is None:
				return False
			self.WriteHold(page, struct.pack('>QH', boff, 0))
			self.WriteHold(200 + level * 8, struct.pack('>Q', page))
			next = boff
			boff = page
			top = 0
			
		# push chunk into bucket
		self.WriteHold(boff + 10 + top * 8, struct.pack('>Q', chunk))
		self.WriteHold(boff, struct.pack('>QH', next, top + 1))
		self.DoWriteHold()

		
	def FillLevelOnce(self, level):
		#print('filling in level:%s' % level)
		if level + 1 >= self.levels:
			return False
		chunk = self.PullChunk(level + 1)
		if chunk is None:
			# try to fill this level
			return False
		# okay we have a chunk from the upper level, now
		# lets split it and place it into this level
		#print('broke chunk %x size:%x into %x and %x of size %x' % (chunk, self.base << (level + 1), chunk, chunk + (self.base << level), self.base << level))
		self.PushChunk(level, chunk + (self.base << level))
		self.PushChunk(level, chunk)
		return True
	
	def PullChunk(self, level = 0):
		slackpages = []
		ret = self.__PullChunk(level, slackpages)
		self.PushBasePages(slackpages)
		return ret
		
	def __PullChunk(self, level, slackpages):
		#print('pulling chunk from level:%s' % level)
		#print('pulling chunk from level:%s' % level)
		boff = struct.unpack('>Q', self.Read(200 + level * 8, 8))[0]
		next, top = struct.unpack('>QH', self.Read(boff, 10))
		if top == 0:
			#print('		bucket for level empty')
			# drop this page and get next
			if next == 0:
				#print('			no more buckets')
				# if we have to go any higher we are out of memory
				if level + 1 >= self.levels:
					return None
				# lets try to fill it with some pages
				if self.FillLevelOnce(level) is False:
					#print('			filling level was fale')
					return None
				return self.__PullChunk(level, slackpages)
			self.Write(200 + ulevel * 8, struct.pack('>Q', next))
			# store this unused base sized page
			slackpages.append(boff)
			# try again..
			return self.__PullChunk(level, slackpages)
		chunk = struct.unpack('>Q', self.Read(boff + 10 + (top - 1) * 8, 8))[0]
		#print('		chunk:%s' % chunk)
		self.Write(boff, struct.pack('>QH', next, top - 1))
		#print('returning chunk:%x level:%s top:%s' % (chunk, level, top - 1))
		return chunk

class SimpleFS(ChunkSystem):
	def __init__(self, rip, rport, bid):
		ChunkSystem.__init__(self, rip, rport, bid)
	def Format(self, force = False):
		# format it
		ChunkSystem.Format(self, force)
		# the base for any master meta-data
		self.metabase = 500
		self.Write(self.metabase, struct.pack('>Q', 0))
		
	def EnumerateFileList(self):
		files = []
		cur = struct.unpack('>Q', self.Read(self.metabase, 8))[0]
		while cur != 0:
			# read file header
			print('reading header:%x' % cur)
			next, nchunk, tsize, dlen, nlen = struct.unpack('>QQQQH', self.Read(cur, 8 * 4 + 2))
			# next file, next chunk, tchunksize, datalen, namelen
			# read file name
			
			print('next:%x chunk:%s tsize:%s dlen:%s nlen:%s' % (next, nchunk, tsize, dlen, nlen))
			off = cur + 8 * 4 + 2
			name = []
			while nlen > 0:
				# nlen = name length
				if nlen > tsize:
					clen = tsize
				else:
					clen = nlen
				nlen = nlen - clen
				print('reading name part off:%x clen:%x' % (off, clen))
				name.append(self.Read(off, clen))
				boff = nchunk
				if boff == 0 or nlen < 1:
					break
				nchunk, tsize = struct.unpack('>QQ', self.Read(boff, 8 + 8))
				off = boff + 16
			name = (b''.join(name)).decode('utf8', 'ignore')
			files.append((name, cur))
			# get next file
			cur = next
		return files
	def GetUniqueID(self):
		raise Exception('Not Implement')
	def GetFileListUniqueID(self):
		raise Exception('Not Implement')
	def GetChangeID(self):
		raise Exception('Not Implement')
	def DeleteFile(self, foff):
		raise Exception('Not Implement')
	def WriteFileFromMemory(self, foff, data, off = 0):
		raise Exception('Not Implement')
	def TruncateFile(self, foff, newsize):
		raise Exception('Not Implement')
	def WriteNewFileFromMemory(self, rpath, data):
		chunks = self.AllocChunksForSegment(len(data) + len(rpath))
		
		# [(offset, size, level), ...]
		fchunk = chunks.pop()
		rchunk = fchunk

		f = struct.unpack('>Q', self.Read(self.metabase, 8))[0]
		
		nlen = len(rpath)
		
		# next file, next chunk, tchunksize, namelen
		
		firstheader = True
		
		doff = 0
		
		wdata = rpath + data
		
		while fchunk[1] != 0:
			if len(chunks) > 0:
				nchunk = chunks.pop()
			else:
				nchunk = (0, 0, 0)
			# write header
			print('writing header for chunk:%x nchunk:%x' % (fchunk[0], nchunk[0]))
			if firstheader:
				firstheader = False
				# next file chunk, next chunk in this size, this chunk size, data size, name size
				self.Write(fchunk[0], struct.pack('>QQQQH', f, nchunk[0], fchunk[1], len(data), len(rpath)))
				hdrlen = 8 * 4 + 2
				nextoff = 8
			else:
				# next chunk in this file, this chunk size
				self.Write(fchunk[0], struct.pack('>QQ', nchunk[0], fchunk[1]))
				hdrlen = 8 * 2
				nextoff = 0
				
			if doff < len(wdata):
				# write some file data
				crem = fchunk[1] - hdrlen
				if crem > len(wdata):
					crem = len(wdata) - doff
				print('writing %s bytes of data out of %s' % (crem, len(wdata)))
				self.Write(fchunk[0] + hdrlen, wdata[doff:doff + crem])
				doff = doff + crem
			# lchunk is used at end if more data remaining
			lchunk = fchunk	
			# fchunk is used on next iteration if not (0, 0, 0)
			fchunk = nchunk
		# is there still name data or file data left
		if doff < len(data):
			# allocate one more page
			need = (len(data) - doff) + 8 * 2
			assert(need < 4096)
			chunk = self.PullChunk(0)
			print('allocated final chunk:%x of size:%x' % (chunk, 4096))
			# link from last chunk to this chunk
			self.Write(fchunk[0] + nextoff, struct.pack('>Q', chunk[0]))
			# write our header
			self.Write(chunk[0], struct.pack('>QQ', 0, chunk[1]))
			off = 8 * 2
			# write remaining data
			self.Write(chunk[0] + off, data[doff:])
		
		# i write the 
		self.Write(self.metabase, struct.pack('>Q', rchunk[0]))
		
	def ReadFileIntoMemory(self, rpath, offset = 0, length = None):
		raise Exception('Not Implement')
		
def doClient():
	# 192.168.1.120
	fs = SimpleFS('kmcg3413.net', 1874, bytes(sys.argv[1], 'utf8'))
	fs.Format(force = True)
	fs.WriteFileFromMemory(b'/home/kmcguire/a', b'hella world')
	fs.WriteFileFromMemory(b'/home/kmcguire/b', b'hellb world')
	fs.WriteFileFromMemory(b'/home/kmcguire/c', b'hellc world')
	fs.WriteFileFromMemory(b'/home/kmcguire/d', b'helld world')
	list = fs.EnumerateFileList()
	print(list)
	
	
	
	#fs.TestSegmentAllocationAndFree()


if __name__ == '__main__':
	doClient()
	#for x in range(0, 1):
	#	t = threading.Thread(target = doClient)
	#	t.start()