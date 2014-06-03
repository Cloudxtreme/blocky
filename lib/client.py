import socket
import struct
import random
import timeit
import threading
import os
import sys
import hashlib
import time
import math
import traceback
import inspect

from lib.layers import interface
from lib.layers.SimpleFS import SimpleFS
from lib.layers.ChunkPushPullSystem import ChunkPushPullSystem
from lib.ClientExceptions import *
from lib import pubcrypt

from lib.misc import *
	
'''
	@group:				client-internal
	@sdescription:		This is a structure representing a write hold.
'''
class WriteHold:
	def __init__(self, offset, data, id, vector):
		self.offset = offset
		self.data = data
		self.id = id
		self.vector = vector
	
'''
	@group:				classes
	@sdescription:		This will create a client object and provide access to the remote block.
'''
class Client(interface.StandardClient):
	class NoLinkException(Exception):
		pass

	'''
		@sdescription:		This is the initializer for the Client class. You must
		@+:					provide the arguments like: `client = Client('kmcg3413.net'. 1874, 'myblockid')`.
	'''
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
		
		self.CacheDrop()						# initialize cache system
		self.cache_maxpages = 1024 * 4			# auto-drop-and-flush uses this
		self.cache_autodropandflush = False
		
		self.linkdrophandler = None
		self.linkdropthrowexception = False
		
		self.wholds = []
		
		self.wdbg = []
		
		self.vexecwarnlimit = 1024
		
		self.blocksz = None
		
		# set the defaults
		self.SetCommunicationExceptionTime(60 * 15)
		self.SetRelinkTimeout(35)
		
		self.trans_stack = []
		self.trans_curid = None
		self.trans_idgen = IDGen(4)
		self.trans_depth = 0
	
	'''
		@sdescription:		Will start a transaction session. All writes will be made
		@+:					holding writes meaning they will not happen on the server
		@+:					until TransactionCommit is called. Will flush cache before
		@+:					returning to ensure all writes have been made in preparation
		@+:					for the transaction. It will not flush cache is this is a
		@+:					nested transaction (transaction inside transaction).
	'''
	def TransactionStart(self):
		if self.trans_curid is None:
			# go ahead and flush anything that is dirty
			self.CacheFlush()
			pass
		# this is used for __TransactionRestore
		self.trans_stack.append((self.cache_autodropandflush, self.linkdropthrowexception, self.trans_curid))
		self.trans_curid = struct.unpack('>I', self.trans_idgen.ugen())[0]
		
		# set these like we need them for a transaction; we dont
		# want cache being written and we want an exception thrown
		# if the link fails so we can abort the transaction
		self.cache_autodropandflush = False
		self.linkdropthrowexception = True
		
		self.trans_depth = self.trans_depth + 1
		
		return self.trans_curid
		
	'''
		@sdescription:		Will abort a transaction and restore local cache
		@+:					to an untainted state.
	'''
	def TransactionDrop(self):
		self.trans_depth = self.trans_depth - 1
		# drop the cache because it is dirtied with the
		# write holds that we are not going to execute
		# on the server which would leave it in a inconsistent
		# state when the transaction is restarted (if desired)
		self.CacheDrop()
		# instead of executing with commit we just drop the
		# write holds and consider them never being done
		self.FlushWriteHold()
		# restore previous values
		self.__TransactionRestore()
	
	def __TransactionRestore(self):
		# restore stuff
		res = self.trans_stack.pop()
		self.cache_autodropandflush = res[0]
		self.linkdropthrowexception = res[1]
		self.trans_curid = res[2]
	'''
		@sdescription:		Will execute write holds, and will leave local cache
		@+:					in it's current state which should hold all the writes.
	'''
	def TransactionCommit(self):
		self.trans_depth = self.trans_depth - 1
		# drop cache because everything should be in write holding state
		# (i have changed this since if we execute write hold with success
		#  then the remote server should match our cache)
		#self.CacheFlush()
		# execute the writes being held on the server
		self.DoWriteHold()
		# restore previous values
		self.__TransactionRestore()
	
	'''
		@sdescription:		Will toggle the cache automatically flushing old
		@+:					dirtied pages back to the server. This is called
		@+:					by TransactionStart to prevent automatic flushing
		@+:					of the cache to the server.
	'''
	def SetCacheAutoDropAndFlush(self, value):
		self.cache_autodropandflush = value
	
	'''
		@sdescription:		This will cause link failures to throw an exception
		@+:					which will allow a transaction to be aborted.
	'''
	def SetLinkDropThrowException(self, value):
		self.linkdropthrowexception = value
	
	'''
		@sdescription:		A handler which is called during a link failure.
	'''
	def SetLinkDropHandler(self, handler):
		self.linkdrophandler = handler

	'''
		@group:				shutdown
		@sdescription:		Ensures all outgoing packets have been sent
		@+:					and recieved by the remote end. Also flushes
		@+:					cache to remote.
	'''
	def Finish(self):
		self.CacheFlush()
		while self.GetOutstandingCount() > 0:
			for k in self.outgoing:
				pkt = self.outgoing[k]
			self.HandlePackets()
			time.sleep(0.2)
	'''
		@group:				cache
		@sdescription:		Drop all cache and DO NOT commit any. To commit the cache
		@+:					use CacheFlush.
	'''
	def CacheDrop(self):
		self.cache = {}
		self.cache_dirty = []
		self.cache_lastread = {}
		self.cache_lastwrite = {}
	
	'''
		@group:				cache
		@sdescription:		Will commit the cache to the server. To drop without
		@+:					commiting to server use CacheDrop.
	'''
	def CacheFlush(self):
		# go through all our dirty pages
		for page in self.cache_dirty:
			cache = self.cache[page]
			# write the page to the server
			self.Write(page, cache[page])
			print('flushed cache page %x to server' % page)
		return 
	
	'''
		@group:				cache
		@sdescription:		Determine if we have too many cache pages, and we
		@+:					need to flush some to the server to get back under
		@+:					the limit.
	'''
	def CacheTick(self):
		if self.cache_autodropandflush is False:
			return 
	
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
			# TODO: this could be a problem.. if we write it out and delete the cache
			#       then it does seem possible that a read could occur before the pacet
			#       containing the page to be written on the server essentially reading
			#		any old data
			if oldpage in self.cache_dirty:
				print('CACHE WRITE DIRTY PAGE:%x' % oldpage)
				self.cache_dirty.remove(oldpage)
				self.Write(oldpage, self.cache[oldpage])
			# drop old page
			#print('commiting and dropping cache page %x' % page)
			del self.cache[oldpage]
			if oldpage in self.cache_lastread:
				del self.cache_lastread[oldpage]
			if oldpage in self.cache_lastwrite:
				del self.cache_lastwrite[oldpage]
	'''
		@group:				cache
		@sdescription:		Read from the cache lines.
	'''
	def CacheRead(self, offset, length):
		assert(length > 0)
		assert(offset > -1)
	
		cache = self.cache
		# align to page boundary
		page = offset & ~0x3ff
		# break offset down into local page offset
		dleft = length
		
		ct = time.time()
		
		# eliminate this kinda call
		if self.blocksz is None:
			self.blocksz = self.GetBlockSize()
		
		#print('cache read offset:%x length:%x' % (offset, length))
		
		out = []
		while dleft > 0:
			if page not in cache:
				self.CacheTick()
				# oops.. this sucks.. we need to check that we are
				# not going to read past the end of our remote block
				# and if we are cut this cache line short in size
				if page >= self.blocksz:
					print('offset:%x blocksz:%x' % (offset, self.blocksz))
					raise OperationException('read past end of virtual block device')
				if page + 1024 >= self.blocksz:
					psz = self.blocksz - page
				else:
					psz = 1024
				cache[page] = self.Read(page, psz, block = True, cache = False)
				#print('loading page:%x from cache' % page)
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
	'''
		@group:				cache
		@sdescription:		Writes to the cache lines.
	'''
	def CacheWrite(self, offset, data, wt = False):
		cache = self.cache
		
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

	'''
		@group:				write-hold
		@sdescription:		Get the write hold count on the server for the
		@+:					specified ID.
	'''
	def GetWriteHoldCount(self, id = None):
		self.DoBlockingLinkSetup()

		if id is None:
			# see if transaction is currently on-going
			# and if so use that ID, otherwise use the
			# default id of zero
			if self.trans_curid != None:
				id = self.trans_curid
			else:
				id = 0
		
		_data = struct.pack('>BI', PktCodeClient.GetWriteHoldCount, id)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		ret = self.HandlePackets(getvector = vector)
		if ret is None:
			raise OperationException()
		
		return ret
	'''
		@group:			write-hold
		@sdescription:	Tell the server to drop the write holds for the
		@+:				specified ID.
	'''
	def FlushWriteHold(self, id = None, block = False, discard = True, ticknet = False):
		if id is None:
			# see if transaction is currently on-going
			# and if so use that ID, otherwise use the
			# default id of zero
			if self.trans_curid != None:
				id = self.trans_curid
			else:
				id = 0

		_data = struct.pack('>BI', PktCodeClient.FlushWriteHold, id)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
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
		
	'''
		@group:			write-hold
		@sdescription:	Execute the write holds for the specified ID on the server.
	'''
	def DoWriteHold(self, block = False, discard = True, verify = True, ticknet = False, id = None):
		self.DoBlockingLinkSetup()
		
		#st = time.time()
		
		if id is None:
			# see if transaction is currently on-going
			# and if so use that ID, otherwise use the
			# default id of zero
			if self.trans_curid != None:
				id = self.trans_curid
			else:
				id = 0

		# we need to make sure all the writes for this hold
		# have arrived at the server... first let us check
		# that indeed we have got an acknowledge for them
		# all from the server
		if verify:
			tryagain = True
			while tryagain:
				allthere = False
				while allthere is False:
					allthere = True
					for hold in self.wholds:
						holdid = hold.id
						if holdid != id:
							continue
						vec = hold.vector
						if vec not in self.vexecuted or self.vexecuted[vec] == None:
							#print('vec:%s not here yet' % vec)
							#print(self.vexecuted)
							allthere = False
							break
					if allthere is True:
						# exit and then verify once again that
						# they are all there
						#print('all vectors in place')
						break
					# let the network tick and get them there
					#print('resending packets count:%s' % len(self.outgoing))
					self.HandlePackets()
					# sleep just a little to take some load
					# off the CPU while we loop here..
					time.sleep(0)
				
				#tt = time.time() - st
				#print('total-time:%s' % tt)
				
				# remove them from vexecuted (only ones matching ID)
				for hold in self.wholds:
					if hold.id == id:
						vec = hold.vector
						if vec in self.vexecuted:
							del self.vexecuted[vec]
			
				# get server count of writes on hold to verify they are all there
				scnt = self.GetWriteHoldCount(id = id)
				
				# get local count
				lcnt = 0
				for hold in self.wholds:
					if hold.id == id:
						lcnt = lcnt + 1
				
				# are all the writes there?
				if lcnt != scnt:
					# flush the ones there if any (wait for response)
					self.FlushWriteHold(id = id, block = True)
					# try to re-send them
					print('resending holds')
					holdput = []
					_toremove = []
					for hold in self.wholds:
						# make sure the ID is right
						if hold.id == id:
							# send the write hold
							self.WriteHold(hold.offset, hold.data, block = True, holdput = holdput)
							print('	sending hold with id:%s|%s offset:%s data-size:%s' % (hold.id, id, hold.offset, len(hold.data)))
							_toremove.append(hold)
					# remove the old holds (old vector)
					for hold in _toremove:
						self.wholds.remove(hold)
					# add the new holds (new vector)
					for hold in holdput:
						self.wholds.append(hold)
					# re-check they are all there
					# (loop again)
				else:
					# exit the loop
					tryagain = False
		
		_data = struct.pack('>BI', PktCodeClient.DoWriteHold, id)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)

		# flush the write holds on our side
		_toremove = []
		for hold in self.wholds:
			if hold.id == id:
				_toremove.append(hold)
		for hold in _toremove:
			self.wholds.remove(hold)
		_toremove = None
		
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
	'''
		@group:			write-hold
		@sdescription:	Loads a write hold onto the server using the current
		@+:				transaction ID, or zero is no transaction is current.
	'''
	def WriteHold(self, offset, data, block = False, discard = True, ticknet = False, wt = True, holdput = True):
		return self.Write(offset, data, block = block, hold = True, discard = discard, ticknet = ticknet, wt = wt, holdput = holdput)
	
	if __debug__:
		def DebugPrintWhoWrote(self, offset, length):
			print('	DEBUG-WHO-WROTE		offset:%x length:%x' % (offset, length))
			for dbg in self.wdbg:
				s = dbg[2]
				e = s + dbg[3]
				_s = offset
				_e = offset + length
				if	(_s >= s and _s <= e) or (_e >= s and _e <= e) or (s >= _s and s <= _e) or (e >= _s and e <= _e):
					print('		f:%s l:%s offset:%x length:%x' % (dbg[0], dbg[1], s, length))
			return True
	
	'''
		@group:			data
		@sdescription:	Executes the write on the server immediantly, unless an transaction
		@+:				is active then it is executed as a write hold.
	'''
	def Write(self, offset, data,  block = False, hold = False, discard = True, cache = True, wt = True, ticknet = False, holdput = True):
		# track who called us and the write data
		#self.wdbg
		#frm = inspect.stack()[1]
		#callername = inspect.getmodule(frm[0])
		#sourcefile = inspect.getsourcefile(frm[0])
		##sourceline = inspect.getsourcelines(frm[0])[1]
		#sourceline = frm[0].f_lineno
		#self.wdbg.append((sourcefile, sourceline, offset, len(data)))		
		#print(sourcefile, sourceline)
		#exit()
		
		# split the write up if we need too if it is very large
		if len(data) < 1200:
			return self.__Write(offset, data, block = block, hold = hold, discard = discard, cache = cache, wt = wt, ticknet = ticknet, holdput = holdput)
		loffset = 0
		rets = []
		while loffset < len(data):
			lsz = 1200
			if lsz > len(data) - loffset:
				lsz = len(data) - loffset
			_data = data[loffset:loffset + lsz]
			
			ret = self.__Write(offset + loffset, _data, block = block, hold = hold, discard = discard, cache = cache, wt = wt, ticknet = ticknet, holdput = holdput)
			
			rets.append(ret)
			
			# update this last for 'offset + loffset' above
			loffset = loffset + lsz
		return rets
	
	def __Write(self, offset, data, block = False, hold = False, discard = True, cache = True, wt = True, ticknet = False, holdput = True):
		self.DoBlockingLinkSetup()
		
		# force any writes to be held if inside a
		# transaction block
		id = 0
		if hold or self.trans_curid is not None:
			# see if transaction is currently on-going
			# and if so use that ID, otherwise use the
			# default id of zero
			if self.trans_curid is not None:
				id = self.trans_curid
			code = PktCodeClient.WriteHold
			_data = struct.pack('>BQI', code, offset, id) + data
			
			# disable this so it does not overwrite ours
			discard = True
			# set the catch to add the write hold to our
			# internal list and also be able to record
			# the vector used
			catchforhold = True
		else:
			catchforhold = False
			code = PktCodeClient.Write
			_data = struct.pack('>BQ', code, offset) + data
	
		# serves mainly to allow reads from cache to work properly
		# you can still block or not block on your writes
		if cache:
			self.CacheWrite(offset, data, wt = wt)
			# if write-through not set then just return (only write to cache)
			if wt is False:
				return
		
		# <message> was built up at top of this method
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if catchforhold:
			# only add to holds by default; when we resend holds (because some got
			# lost for whatever reason) this function is called 
			if holdput is not True:
				holdput.append(WriteHold(offset, data, id, vector))
			else:
				self.wholds.append(WriteHold(offset, data, id, vector))
			self.vexecuted[vector] = None
		
		# does not make sense to discard and block (will just fil up vexecuted)
		if discard is not True and block is False:
			# discard the write reply when it arrives
			self.vexecuted[vector] = discard

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
		@group:					data
		@sdescription:			This will copy data in the remote block.
		@ldescription:			This is much faster because it data is never transferred. To
		@+:					    get the same effect you could use a read and then write but
		@+:   					it would suffer in performance.
		@param.dst:				destination byte address
		@param.src:				source byte address
		@param.length:			length in bytes
		@param.cache:			if false cache is not involved in this transaction
		@param.ticknet:			during this call any waiting packets will be processed
		@param.discard:			discard the results if any
		@param.wt:				if cache is True then write-through the cache if True
		@return:				the result of the operation if block is True
	'''
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
		
	'''
		@group:					data
		@sdescription:			This will read data from the remote block.
		@param.offset:			source byte address
		@param.length:			length in bytes
		@param.cache:			if false cache is not involved in this transaction
		@param.ticknet:			during this call any waiting packets will be processed
		@param.discard:			discard the results if any
		@return:				the result of the operation if block is True
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
	
	'''
		@group:			data
		@sdescription:	This will perform an atomic exhange on the server immediantly.
	'''
	def Exchange8(self, offset, newval):
		self.DoBlockingLinkSetup()
		
		_data = struct.pack('>BQ', PktCodeClient.Exchange8, offset) + data
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if block is False:
			vector = None
		ret = self.HandlePackets(getvector = vector)
		if block and ret is False:
			raise OperationException()
		return ret
	
	'''
		@group:			locking
		@sdescription:	Establishes a auto-write on link drop/failure.
	'''
	def BlockLock(self, offset, value = 0):
		self.DoBlockingLinkSetup()
		
		_data = struct.pack('>BQI', PktCodeClient.BlockLock, offset, value)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		# always block on this call and return result
		ret = self.HandlePackets(getvector = vector)
		return ret
	
	'''
		@sdescription:	Will remove an auto-write on link drop/failure.
	'''
	def BlockUnlock(self, offset, block = True):
		self.DoBlockingLinkSetup()
	
		_data = struct.pack('>BQ', PktCodeClient.BlockUnlock, offset)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if block is False:
			vector = None
		ret = self.HandlePackets(getvector = vector)
		# if blocking return the value
		if block:
			return ret
		# if not-blocking just return success
		return True
	'''
		@sdescription:	Will return the total size of the remote block on the server in bytes.
	'''
	def GetBlockSize(self, block = True):
		self.DoBlockingLinkSetup()
		
		_data = struct.pack('>B', PktCodeClient.BlockSize)
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)
		
		if block is False:
			vector = None
		ret = self.HandlePackets(getvector = vector)
		if block and ret is False:
			raise OperationException()
		return ret
	'''
		@sdescription:	The minimum amount of time to wait until relinking is aborted.
	'''
	def SetCommunicationExceptionTime(self, timeout):
		self.commexctimeout = timeout
	
	'''
		@sdescription:	The minimum amount of time to consider a link dead.
	'''
	def SetRelinkTimeout(self, timeout):
		self.relinkafter = timeout
	
	'''
		@sdescription:	Will attempt to relink. Will not return until link is established.
	'''
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
				if time.time() - st > 8:
					break
				time.sleep(0)
				# check if we have been trying for way too long
				# because the main application might want to do
				# other things, or even release any file locks
				# that it holds
				
				# if commexctimeout is enabled and the time specified has elapsed
				if self.commexctimeout is not None and time.time() - ts > self.commexctimeout:
					raise CommunicationException()
					
	'''
		@sdescription:	Get the count of outstanding packets. A packet is outstanding if
		@+:				the server has not ackowledged it.
	'''
	def GetOutstandingCount(self):
		return len(self.outgoing)
	
	def SetVectorExecutedWarningLimit(self, limit):
		self.vexecwarnlimit = limit
	def GetVectorExecutedWarningLimit(self):
		return self.vexecwarnlimit
		
	'''
		@sdescription:	Will handle reading any incoming packets, and sending (or re-sending)
		@+:				any packets in the outgoing queue.
	'''
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
					if out[1] > 0:
						print('.', end='')
						sys.stdout.flush()
					# it has been too long so resend it
					if self.crypter != out[3]:
						# grab the old vector
						oldvector = out[0]
						# re-encrypt the data
						data, vector = BuildEncryptedMessage(self.link, out[4])
						#outgoing[vector] = (vector, out[1], data, self.crypter, data[4])
						toadd.append((vector, 0, data, self.crypter, out[4]))
						# schedule the old vector to be removed
						toremove.append(out[0])
						# do not send old vector, just skip it
						print('re-encrypted old-vector:%s new-vector:%s' % (oldvector, vector))
						# if we were waiting for this packet then we need to
						# reset it to the new vector numeral
						if out[0] == getvector:
							getvector = vector
						# check if it was in write holds and change vector
						for hold in self.wholds:
							print('checking write hold for remapping after re-encryption')
							if hold.vector == oldvector:
								print('got old vector:%s for write hold as new:%s' % (oldvector, vector))
								# see if result is in self-vexecuted
								if oldvector in self.vexecuted:
									print('		rekeyed results')
									# rekey it with new vector and remove old
									self.vexecuted[vector] = self.vexecuted[oldvector]
									del self.vexecuted[oldvector]
								# set vector to new vector
								hold.vector = vector
						continue
					try:
						self.sock.send(out[2])
					except Exception as e:
						#print('WARNING: socket exception')
						#traceback.print_exc(file = sys.stdout)
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
			#print('handlerelink:%s a:%s b:%s relinkafter:%s' % (handlerelink, ct - self.lmst, ct - self.lmt, self.relinkafter))
			#print('handlerelink:%s' % handlerelink)
			if handlerelink and len(self.outgoing) > 0 and ct - self.lmst > self.relinkafter and ct - self.lmt > self.relinkafter:
				self.linkvalid = False
				print('communications timeout')
				# okay link is considered bad, try to setup a link again
				if self.linkdrophandler is not None:
					# this can throw and exception if it desired to do so
					self.linkdrophandler()
				if self.linkdropthrowexception is True:
					raise LinkDropException()
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
					data, addr = self.sock.recvfrom(4096)
				except Exception:
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
						# record last time we recieved a non-nolink message
						self.lmt = time.time()		
					except Client.NoLinkException:
						# at this point we were either blocking for a specific
						# packet, or we were just ticking the net in any case
						# just break out and let 
						#print('no link so exiting loop')
						break
					
					if match is None:
						# unknown packet
						continue
					
					# remove vector from outgoing (blocking or non-blocking)
					if vector is not None:
						# had this happen, not sure
						if vector in self.outgoing:
							if vector in self.vexecuted:
								# i dunno.. having to do this here too..
								self.vexecuted[vector] = ret
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
								#print('added to vexecuted for vector:%s' % vector)
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
	
	'''
		@sdescription:	Will process an **unencrypted packet**.
	'''
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
				self.link['vman'].Flush()
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
			print('.... LINK VALID!')
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
		elif	type == PktCodeServer.BlockLockSuccess:
				vector = struct.unpack_from('>Q', data)[0]
				if vector == getvector:
					return (True, vector, True)
				return (True, vector, False)
		elif 	type == PktCodeServer.BlockLockFailed:
				vector = struct.unpack_from('>Q', data)[0]
				if vector == getvector:
					return (False, vector, True)
				return (False, vector, False)
		elif	type == PktCodeServer.BlockUnlockFailed:
				vector, offset, force = struct.unpack_from('>QQB', data)
				if vector == getvector:
					return (False, vector, True)
				return (False, vector, False)
		elif	type == PktCodeServer.BlockUnlockSuccess:
				vector, offset = struct.unpack_from('>QQ', data)
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
		try:
			self.sock.send(data)
		except:
			pass
		
	def SetupEncryption(self):
		key = IDGen.gen(512)
		self.link['crypter'] = SymCrypt(key)
		crypter = self.link['crypter']
		self.crypter = crypter
		# encrypt key with public key
		key = pubcrypt.crypt(key, self.pubkey)
		data = struct.pack('>BI', PktCodeClient.SetupEncryption, self.nid) + key
		try:
			self.sock.send(data)
		except:
			pass
				
	def ConnectBlock(self, bid):
		sock = self.sock
		_data = struct.pack('>BI', PktCodeClient.BlockConnect, self.nid) + bid
		data, vector = BuildEncryptedMessage(self.link, _data)
		self.outgoing[vector] = (vector, 0, data, self.crypter, _data)

	'''
		@sdescription:	Warning: This function will corrupt any data on the block target. This is
		@+:				used to test the local cache algorithms, but will also write to the server.
	'''
	def UnitTestCache(self):
		bsz = self.GetBlockSize()
		fd = open('tmp', 'w')
		fd.truncate(bsz)
		fd.close()
		fd = open('tmp', 'r+b')
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
		
			while True:
				off = random.randint(1, bsz - 1)
				sz = random.randint(1, 1024 * 20)
				if off + sz < bsz:
					break
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



