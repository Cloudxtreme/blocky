import layers.interface
import struct
import random
import time

class ChunkPushPullSystem(layers.interface.ChunkSystem):
	ChunkFree 		= 1
	ChunkBegin		= 2
	ChunkData		= 3
	
	def GetBasePageSize(self):
		return self.base
	
	def GetLevelCount(self):
		return self.levels
	
	def __init__(self, client, load = True):
		self.client = client

		if load:
			Load()
		else:
			self.levels = 28
			self.base = 4096
			self.bucketmaxslots = int((self.base - 10) / 8)
		
	def Load(self):
		levels, doffset, base = struct.unpack('>IQQ', client.Read(100, 4 + 8 * 2))
		self.levels = levels
		self.base = base
		self.doffset = doffset
		
	def Format(self, csize = 4096):
		client = self.client
	
		sig = client.Read(0, 8)
		# lets clear the signature field
		client.Write(0, bytes((0, 0, 0, 0, 0, 0, 0, 0)))
		# get block size
		bsz = client.GetBlockSize()
				
		levels = self.levels
		
		print('max storage size:%s' % ((4096 << (levels - 1)) * 510))
		
		#levelsize = 4096 << level
		
		# reserve 4096 bytes for the initial level stack for each and 4096 bytes for the master area
		doffset = 4096 * levels + 4096
		self.doffset = doffset
		
		# save this in the header
		client.Write(100, struct.pack('>IQQ', levels, doffset, self.base))
		
		# max 510 entries per bucket
		for levelndx in range(0, levels):
			# [next][top]
			client.Write(levelndx * 4096 + 4096, struct.pack('>QH', 0, 0))
			client.Write(200 + levelndx * 8, struct.pack('>Q', levelndx * 4096 + 4096))
		
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
			
			client.Write(boff, struct.pack('>QH', 0, wgb))
			
			for i in range(0, wgb):
				client.Write(boff + (8 + 2) + i * 8, struct.pack('>Q',  cmoff))
				print('cmoff:%x' % cmoff)
				# track our current data position in the block
				cmoff = cmoff + fsz
			# decrease chunk size
			fsz = fsz >> 1
			clevel = clevel - 1
	
		print('done cs format')
		client.Write(0, b'cmancman')
		return

	def UnitTest(self):
		client = self.client
	
		tpb = 0
		tpbc = 0
		lsz = 0
		
		client.SetVectorExecutedWarningLimit(2048)		
		segments = []
		while True:
			# let the network do anything it needs to do
			if client.GetOutstandingCount() >= 100:
				while client.GetOutstandingCount() >= 100:
					client.HandlePackets()
		
			sz = random.randint(1, 1024 * 1024 * 100)
			
			st = time.time()
			chunks = self.AllocChunksForSegment(sz)
			tt = time.time() - st
			
			tpb = tpb + (tt / (sz / 1024 / 1024 / 1024))
			tpbc = tpbc + 1
			
			print('avg-time-GB:%s large-alloc:%s this-time:%s' % (tpb / tpbc, lsz, tt))
			
			#print(chunks)
			
			if chunks is None:
				# free something
				st = time.time()
				if len(segments) < 1:
					continue
				#exit()
				i = random.randint(0, len(segments) - 1)
				for chunk in segments[i]:
					self.PushChunk(chunk[2], chunk[0])
				
				del segments[i]
				tt = time.time() - st
				print('freeing:%s' % tt)
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
			client.HandlePackets()
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
		client = self.client
		
		level = 0
		boff = struct.unpack('>Q', client.Read(200 + level * 8, 8))[0]
		next, top = struct.unpack('>QH', client.Read(boff, 10))
		if top == self.bucketmaxslots:
			# create new bucket from one of the pages
			client.WriteHold(page, struct.pack('>QH', boff, 0))
			client.WriteHold(200 + level * 8, struct.pack('>Q', page))
			client.DoWriteHold()
			return True
		# push a page into the bucket
		client.WriteHold(boff + 10 + top * 8, struct.pack('>Q', page))
		client.WriteHold(boff, struct.pack('>QH', next, top + 1))
		client.DoWriteHold()
		return True
		
	def PushChunk(self, level, chunk):
		client = self.client
		# short-circuit to the specialized function for pages (not chunks)
		#print('push-chunk level:%s chunk:%x' % (level, chunk))
		if level == 0:
			return self.PushBasePage(chunk)
		boff = struct.unpack('>Q', client.Read(int(200 + level * 8), 8))[0]
		next, top = struct.unpack('>QH', client.Read(boff, 10))
		if top == self.bucketmaxslots:
			# create new bucket from ... a page (base page / base chunk)
			page = self.PullChunk(0)
			if page is None:
				return False
			client.WriteHold(page, struct.pack('>QH', boff, 0))
			client.WriteHold(200 + level * 8, struct.pack('>Q', page))
			next = boff
			boff = page
			top = 0
			
		# push chunk into bucket
		client.WriteHold(boff + 10 + top * 8, struct.pack('>Q', chunk))
		client.WriteHold(boff, struct.pack('>QH', next, top + 1))
		client.DoWriteHold()

		
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
		client = self.client
		#print('pulling chunk from level:%s' % level)
		#print('pulling chunk from level:%s' % level)
		boff = struct.unpack('>Q', client.Read(200 + level * 8, 8))[0]
		next, top = struct.unpack('>QH', client.Read(boff, 10))
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
			client.Write(200 + level * 8, struct.pack('>Q', next))
			# store this unused base sized page
			slackpages.append(boff)
			# try again..
			return self.__PullChunk(level, slackpages)
		chunk = struct.unpack('>Q', client.Read(boff + 10 + (top - 1) * 8, 8))[0]
		#print('		chunk:%s' % chunk)
		client.Write(boff, struct.pack('>QH', next, top - 1))
		#print('returning chunk:%x level:%s top:%s' % (chunk, level, top - 1))
		return chunk
		
	def GetClient(self):
		return self.client