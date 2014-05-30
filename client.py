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
import layers.interface as interface
import traceback
from layers.SimpleFS import SimpleFS
from layers.ChunkPushPullSystem import ChunkPushPullSystem

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
class Client(interface.StandardClient):
	class NoLinkException(Exception):
		pass

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
		self.cache_maxpages = 8192
		
		self.wholds = []
		
		self.x = 0				# debugging variable (safe to remove)
		self.catchwrite = None
		
		self.vexecwarnlimit = 1024
		
		# set the defaults
		self.SetCommunicationExceptionTime(60 * 15)
		self.SetRelinkTimeout(60 * 5)
		
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

	def Finish(self):
		self.CacheFlush()
		while self.GetOutstandingCount() > 0:
			for k in self.outgoing:
				pkt = self.outgoing[k]
			self.HandlePackets()
			time.sleep(0.2)
		
	def CacheFlush(self):
		# go through all our dirty pages
		for page in self.cache_dirty:
			cache = self.cache[page]
			# write the page to the server
			self.Write(page, cache[page])
			print('flushed cache page %x to server' % page)
		return
	
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
			#print('commiting and dropping cache page %x' % page)
			del self.cache[oldpage]
			if oldpage in self.cache_lastread:
				del self.cache_lastread[oldpage]
			if oldpage in self.cache_lastwrite:
				del self.cache_lastwrite[oldpage]
		
	def CacheRead(self, offset, length):
		assert(length > 0)
		assert(offset > -1)
	
		cache = self.cache
		# align to page boundary
		page = offset & ~0x3ff
		# break offset down into local page offset
		dleft = length
		
		ct = time.time()
		
		out = []
		while dleft > 0:
			if page not in cache:
				self.CacheTick()
				# oops.. this sucks.. we need to check that we are
				# not going to read past the end of our remote block
				# and if we are cut this cache line short in size
				blocksz = self.GetBlockSize()
				if page >= blocksz:
					raise OperationException('read past end of virtual block device')
				if page + 1024 >= blocksz:
					psz = blocksz - page
				else:
					psz = 1024
				cache[page] = self.Read(page, psz, block = True, cache = False)
				#print('loading page:%x' % page)
				assert(len(cache[page]) == psz)
				#print('[read] cache page:%x length:%x' % (page, len(cache[page])))
			self.cache_lastread[page] = ct
			# either a partial read or a full read
			#print('		dleft:%x loffset:%x' % (dleft, loffset))
			
			loffset = offset - page
			
			if dleft > 1024 - loffset:
				ava = 1024 - loffset
			else:
				ava = dleft
			dleft = dleft - ava
			
			#print('read page:%x loffset:%x' % (page, loffset))
			data = cache[page][loffset:loffset + ava]
			out.append(data)
			
			
			offset = offset + ava
			page = offset & ~0x3ff
		
		out = b''.join(out)
		assert(len(out) == length)
		return out
	
	def CacheWrite(self, offset, data, wt = False):
		cache = self.cache
		
		if self.catchwrite is not None:
			if offset >= self.catchwrite[0] and offset < self.catchwrite[1]:
				raise Exception('caught write')
		
		page = offset & ~0x3ff
		loffset = offset - page
		dleft = len(data)
		
		ct = time.time()
		
		while dleft > 0:
			#print('[write] cache loffset:%x page:%x dleft:%x' % (loffset, page, dleft))
			if page not in cache:
				self.CacheTick()
				#print('loading page:%x' % page)
				cache[page] = self.Read(page, 1024, block = True, cache = False)
				#print('[write] cached page:%x' % page)
			if wt is False:
				# its only dirty if the write didnt happen on the server
				self.cache_dirty.append(page)
			self.cache_lastwrite[page] = ct
			#print('done')
			
			loffset = offset - page
			
			# either a partial write or full write
			if dleft > 1024 - loffset:
				lsize = 1024 - loffset
			else:
				lsize = dleft
				
			#print('cache write offset:%x loffset:%x lsize:%s' % (offset, loffset, lsize))
			
			# this looks ugly but how else can i do it quickly...?
			cpage = cache[page]
			
			doff = len(data) - dleft
			
			towrite = data[doff:doff + lsize]
			
			#print('write page:%x loffset:%x data:%s' % (page, loffset, towrite))
			cache[page] = cpage[0:loffset] + towrite + cpage[loffset + lsize:]
			
			assert(len(cache[page]) == 1024)
			
			# subtract what we wrote
			dleft = dleft - lsize
			
			offset = offset + lsize
			page = offset & ~0x3ff
		
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
		# split the write up if we need too if it is very large
		if len(data) < 1200:
			return self.__Write(offset, data, block = block, hold = block, discard = discard, cache = cache, wt = wt, ticknet = ticknet)
		loffset = 0
		rets = []
		print('doing multiple write')
		while loffset < len(data):
			lsz = 1200
			if lsz > len(data) - loffset:
				lsz = len(data) - loffset
			_data = data[loffset:loffset + lsz]
			
			print('loffset:%s' % loffset)
			
			ret = self.__Write(offset + loffset, _data, block = block, hold = block, discard = discard, cache = cache, wt = wt, ticknet = ticknet)
			rets.append(ret)
			
			# update this last for 'offset + loffset' above
			loffset = loffset + lsz
		return rets
	
	def __Write(self, offset, data, block = False, hold = False, discard = True, cache = True, wt = True, ticknet = False):
		self.DoBlockingLinkSetup()
		
		if hold:
			code = PktCodeClient.WriteHold
		else:
			code = PktCodeClient.Write
	
		# serves mainly to allow reads from cache to work properly
		# you can still block or not block on your writes
		if cache:
			self.CacheWrite(offset, data, wt = wt)
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

	def Copy(self, dst, src, length, block = True, cache = True, ticknet = False, discard = True, wt = True):
		if cache:
			ret = self.CacheRead(src, length)
			if ret is None:
				return ret
			self.CacheWrite(dst, ret, wt = wt)
			
		_data = struct.pack('>BQQQ', PktCodeClient.Copy, dst, src, length)
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
		
	def SetCommunicationExceptionTime(self, timeout):
		self.commexctimeout = timeout
	def SetRelinkTimeout(self, timeout):
		self.relinkafter = timeout
		
	def DoBlockingLinkSetup(self):
		ts = time.time()
		
		while self.linkvalid is False:
			# try to setup link
			print('getting public key')
			self.GetPublicKey()
			st = time.time()
			while self.linkvalid is False:
				# do not handle relinks and timeout after 5 seconds which
				# will allow us to rehandle it here
				self.HandlePackets(handlerelink = False, timeout = 5)
				# if too much time passes, abort and try again
				if time.time() - st > 15:
					break
				time.sleep(0)
				# check if we have been trying for way too long
				# because the main application might want to do
				# other things, or even release any file locks
				# that it holds
				
				# if commexctimeout is enabled and the time specified has elapsed
				if self.commexctimeout is not None and time.time() - ts > self.commexctimeout:
					raise CommunicationException()
	def GetOutstandingCount(self):
		return len(self.outgoing)
	def SetVectorExecutedWarningLimit(self, limit):
		self.vexecwarnlimit = limit
	def GetVectorExecutedWarningLimit(self):
		return self.vexecwarnlimit
	def HandlePackets(self, getvector = None, handlerelink = True, timeout = None):
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
					if out[1] == 0:
						# record the last time we send a packet but
						# do not include any resends (because they
						# can indicate a need to re-establish the
						# link)
						self.lmst = ct
					# it has been too long so resend it
					if self.crypter != out[3]:
						# re-encrypt the data
						data, vector = BuildEncryptedMessage(self.link, out[4])
						#outgoing[vector] = (vector, out[1], data, self.crypter, data[4])
						toadd.append((vector, 0, data, self.crypter, out[4]))
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
						traceback.print_exc(file = sys.stdout)
						continue
					# update time last sent
					outgoing[out[0]] = (out[0], ct, out[2], out[3], out[4])
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
			
			
			# if we have not send a message (first time send)
			# after so long AND we have not recieved a message
			# AND we are supposed to handle the relink then attempt
			# to relink
			#print('handlerelink:%s lmst-delta:%s lmt-delta:%s' % (handlerelink, ct - self.lmst, ct - self.lmt))
			if handlerelink and len(self.outgoing) > 0 and ct - self.lmst > self.relinkafter and ct - self.lmt > self.relinkafter:
			#if handlerelink and self.lmt > 0 and self.lmst - self.lmt > self.relinkafter:
				# okay link is considered bad, try to setup a link again
				self.linkvalid = False
				self.DoBlockingLinkSetup()
			
			if timeout is not None and time.time() - ter > timeout:
				return
			
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
					try:
						self.sock.send(_data)
					except Exception as e:
						pass
									
				if encrypted is False or self.link['vman'].IsVectorGood(svector) is True:
					# continue processing packet
					try:
						ret, vector, match = self.HandlePacket(data, getvector = getvector)
					except Client.NoLinkException as e:
						# decided not to handle nolink packets
						#if handlerelink:
						#	self.linkvalid = False
						#	self.DoBlockingLinkSetup()
						#	continue
						# we have been called by DoBlockingLinkSetup for handlerelink to be False
						return
					
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
				data = data[4:]								# drop NID off
				esz = struct.unpack_from('>I', data)[0]		# get exponent size in bytes
				data =  data[4:]							# drop exponent size off
				exp = data[0:esz]							# get exponent
				key = data[esz:]							# get key
				
				self.pubkey = (exp, key)
				
				print('setup encryption')
				self.SetupEncryption()
		elif 	type == PktCodeServer.EstablishLink:
			# we have established a link
			print('established link')
			nid = struct.unpack_from('>I', data)[0]
			if nid == self.nid:
				data = data[4:]
				if 'ulid' in self.link:
					print('link changed from old:%s to new:%s' % (self.link['ulid'], data))
				self.link['vman'] = VectorMan()
				self.link['ulid'] = data
				print('connecting to block')
				self.ConnectBlock(self.bid)
		elif	type == PktCodeServer.BlockConnectFailure:
			nid, vector = struct.unpack_from('>IQ', data)[0]
			if nid == self.nid:
				raise Exception('Failure Connecting To Block')
			return (True, vector, False)
		elif	type == PktCodeServer.NoLink:
			self.linkvalid = False
			#print('no link so doing reconnect')
			raise Client.NoLinkException()
		elif 	type == PktCodeServer.BlockConnectSuccess:
			nid, vector = struct.unpack_from('>IQ', data)
			# TODO: this could be trouble... link delay.. server queues
			# up block connect... then later client relinks up.. gets
			# older one.. screws things up maybe?
			self.linkvalid = True
			if vector == getvector:
				return (True, vector, True)
			return (True, vector, False)
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
		key = IDGen.gen(512)
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

	'''
		This will attempt to verify that indeed the cache is working
		correctly. On each iteration it generates a random length 
		string of data and writes it to a random offset. It then
		reads the string back. This mainly tests writes and reads
		across cache boundaries, and ensures that the cache code
		handles these boundaries. If that code is changed this test
		needs to be run to verify that the code still works correctly.
	'''
	def UnitTestCache(self):
		fd = open('tmp', 'r+b')
		bsz = self.GetBlockSize()
		fd.truncate(bsz)
		writes = []
		
		random.seed(340)
		
		'''
		data = IDGen.gen(1200)
		self.Write(0, data)
		_data = self.Read(0, 1200)
		if data != _data:
			print(data[0:10])
			print(_data[0:10])
			print('WRONG')
		exit()
		'''
		
		while True:
			for write in writes:
				off = write[0]
				sz = write[1]
				_data = self.Read(off, sz)
				fd.seek(off)
				data = fd.read(sz)
				if _data != data:
					print(_data)
					print('------------------')
					print(data)
					raise Exception('data does not match')
				else:
					print('match off:%s sz:%s' % (off, sz))
		
			off = random.randint(1, bsz - 1)
			sz = random.randint(1, 1024 * 4)
			if sz > bsz - off:
				sz = bsz - off 
			
			# generate random byte sequence
			data = IDGen.gen(sz)
			
			print('writing offset:%x len:%x' % (off, sz))
			# write to our file
			fd.seek(off)
			fd.write(data)
			# write to the virtual block
			self.Write(off, data)
			# store the write
			writes.append((off, len(data)))
		# execution will never reach here
		return True
		
def doClient(rhost, bid):
	# 192.168.1.120
	client = Client('192.168.1.120', 1874, bytes(bid, 'utf8'))
	
	#client.Read(0, 8)
	#client.UnitTestCache()
	#exit()
	
	cs = ChunkPushPullSystem(client, load = False)
	cs.Format()
	
	#cs.UnitTest()
	#exit()
	
	fs = SimpleFS(cs)

	fs.UnitTest()
	
	client.Finish()
	
'''
key = IDGen.gen(512)
m = SymCrypt(key)
st = time.time()
z = 0

#o = IDGen.gen(1500)
o = b'hello world ABCDEFGHIJKLMNOPQRSTUVWXYZ'

print(key[0:len(o)])

c = m.crypt(o)

print(c)
p = m.decrypt(c)
print(p)
if p != o:
	print('FAILED')
	exit()

z = z + 1
if z > 50:
	z = 0
	print('ps', (time.time() - st) / (x + 1))
exit()
'''

# if main module then execute main routine
if __name__ == '__main__':
	print('Blocky Standard Client')
	print('Leonard Kevin McGuire Jr. 2014')
	print()
	print('WARNING: THIS SOFTWARE IS ALPHA!')
	print()
	
	if len(sys.argv) < 3:
		print('Not Enough Arguments')
		print('<remote-host> <remote-block-id>')
		exit()
		
	doClient(sys.argv[1], sys.argv[2])
	
	# multiple client test
	#for x in range(0, 1):
	#	t = threading.Thread(target = doClient)
	#	t.start()