import layers.interface
import struct
import random
from misc import *

class SimpleFS(layers.interface.BasicFS):
	def __init__(self, cs):
		self.cs = cs
		self.client = cs.GetClient()
		self.metabase = 500
		
	def Format(self):
		client = self.client
		cs = self.cs
		# write our signature field
		client.Write(16, b'sifssifs')
		client.Write(self.metabase, struct.pack('>Q', 0))
		
	def EnumerateFileList(self):
		client = self.client
		files = []
		cur = struct.unpack('>Q', client.Read(self.metabase, 8))[0]
		while cur != 0:
			# read file header
			next, nchunk, tsize, dlen, nlen = struct.unpack('>QQQQH', client.Read(cur, 8 * 4 + 2))
			# next file, next chunk, tchunksize, datalen, namelen
			# read file name
			
			print('		next:%x chunk:%s tsize:%s dlen:%s nlen:%s' % (next, nchunk, tsize, dlen, nlen))
			off = cur + 8 * 4 + 2
			name = []
			while nlen > 0:
				# nlen = name length
				if nlen > tsize:
					clen = tsize
				else:
					clen = nlen
				nlen = nlen - clen
				print('		reading name part off:%x clen:%x' % (off, clen))
				name.append(client.Read(off, clen))
				boff = nchunk
				if boff == 0 or nlen < 1:
					break
				nchunk, tsize = struct.unpack('>QQ', client.Read(boff, 8 + 8))
				off = boff + 16
			name = (b''.join(name)).decode('utf8', 'ignore')
			files.append((name, cur, dlen))
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
	def __PushChunksInChain(self, chunk):
		cs = self.cs
		client = self.client
		
		bpsz = cs.GetBasePageSize()
		while chunk != 0:
			nchunk, size = struct.unpack('>QQ', client.Read(chunk, 16))
			
			print('		pushing chunk:%x size:%x' % (chunk, size))
			
			# calculate level and push chunk back
			level = (size / bpsz) - 1
			
			cs.PushChunk(level, chunk)
			
			chunk = nchunk
	def TruncateFile(self, foff, newsize):
		client = self.client
		cs = self.cs
		next, nchunk, csize, dlen, nlen = struct.unpack('>QQQQH', client.Read(foff, 8 * 4 + 2))
		hoff = 8 * 4 + 2
		chunk = foff
		tsize = 0
		csize = csize - nlen
		print('truncate')
		
		while chunk != 0:
			tsize = tsize + (csize - hoff)
			dlen = dlen - (csize - hoff)
			
			# we are going to have to make it smaller
			if tsize > newsize:
				print('tsize > newsize')
				if nchunk != 0:
					# okay, there is no need for another chunk so
					# we can drop the next chunk and any others
					self.__PushChunksInChain(nchunk)
				# now let us evaluate if this current change
				# can be made smaller and still contain the
				# data
				bpsz = cs.GetBasePageSize()
				level = int((csize / bpsz) - 1)
				while level != 0:
					if bpsz << level < dlen:
						# take previous level
						level = level + 1
						break
					level = level - 1
				
				print('got level:%s original-level:%s' % (level, int(csize / bpsz)))
				
				if level != (csize / bpsz) - 1:
					# allocate new chunk that is smaller for data
					print('level', level)
					_chunk = cs.PullChunk(level)
					if _chunk is None:
						return True
					# copy old chunk data into new chunk
					client.Copy(_chunk, chunk, bpsz << level)
					# correctly set header of new chunk 
					if hoff == 16:
						# child chunk
						client.Write(_chunk, struct.pack('>QQ', 0, bpsz << level))
					else:
						# master chunk >QQQQH
						client.Write(_chunk + 8, struct.pack('>QQ', 0, bpsz << level)) 
					
					# write the 4th field of the master header to show new size
					client.Write(foff + 8 * 3, struct.pack('>Q', newsize))
					
					# exit we are done
					return True
			
			if nchunk == 0:				# if no more chunks then exit
				print('no more chunks')
				break
			chunk = nchunk				# get next chunk 
			hoff = 16
			nchunk, csize = struct.unpack('>QQ', client.Read(chunk, 16))
		_chunk = chunk
		# we are going to have to make it larger
		if tsize < newsize:
			# add some chunks to make up difference
			chunks = cs.AllocChunksForSegment(newsize - tsize)
			
			if chunks is None:
				return False
			
			if hoff == 16:
				hoff = 0
			else:
				hoff = 8
				
			tmp, sz = struct.unpack('>QQ', client.Read(_chunk + hoff, 16))
			
			_chunk = (_chunk, sz)
			for chunk in chunks:
				# just write the address of the next chunk
				# hoff - adjusts for if this is the master chunk
				client.Write(_chunk[0] + hoff, struct.pack('>Q', chunk[0]))
				#print('writeA chunk:%x --> next:%x size:%x' % (_chunk[0], chunk[0], _chunk[1]))
				# write header for new chunk
				client.Write(chunk[0], struct.pack('>QQ', 0, chunk[1]))
				#print('writeB chunk:%x --> next:0 csize:%x' % (chunk[0], chunk[1]))
				# set last chunk to this chunk
				_chunk = chunk
				# if was set to 8 it is now set to 0
				hoff = 0
				# now loop will grab next chunk
			# write the new data size
			client.Write(foff + 8 * 3, struct.pack('>Q', newsize))
		# exit we are done
		return True
	
	def SetNameLength(self, foff, nlen):
		client = self.client
		# get old sizes
		dlen, _nlen = struct.unpack('>QH', client.Read(foff + 8 * 3, 8 + 2))
		# restore bytes
		dlen = dlen + _nlen
		# subtract bytes
		dlen = dlen - nlen
		# write new sizes
		print('dlen:%s nlen:%s' % (dlen, nlen))
		client.Write(foff + 8 * 3, struct.pack('>QH', dlen, nlen))
		
	def CreateFile(self, path, size):
		if type(path) is str:
			path = bytes(path, 'utf8')
		foff = self.AllocateFile(size + len(path))
		self.WriteFile(foff, None, path)
		self.SetNameLength(foff, len(path))
		return foff
		
	def GetNameLength(self, foff):
		client = self.client
		next, nchunk, csize, dlen, nlen = struct.unpack('>QQQQ', client.Read(foff, 8 * 4 + 2))
		return nlen
	
	def ReadFile(self, foff, offset, length):
		return self.__RWFileMemory(foff, length = length, offset = offset)
		
	def WriteFile(self, foff, offset, data):
		return self.__RWFileMemory(foff, offset = offset, data = data, write = True)
		
	def __RWFileMemory(self, foff, offset = 0, length = 0, data = None, write = False):
		client = self.client
		out = []
		chunk = foff
		next, nchunk, csize, dlen, nlen = struct.unpack('>QQQQH', client.Read(foff, 8 * 4 + 2))
		foff = 8 * 4 + 2
		
		# unless they specify None move them past the name string
		if offset is not None:
			offset = nlen + offset
		else:
			offset = 0
			
		if write is True:
			dlen = len(data)
		else:
			dlen = length
		boff = 0
		doffset = 0
		while True:
			# are we current on a chunk where our offset begins
			if boff + csize >= offset:
				# we our offset from base of chunk
				aoff = offset - boff
				
				# the most we can read or write on this chunk
				ava = csize - aoff - foff
				if ava > dlen:
					# if its more than we need then adjust
					ava = dlen
				
				# yes, let us read what we can or need
				if write is False:
					out.append(client.Read(chunk + foff + aoff, ava))
				else:
					print('writing... data-len:%s' % ava)
					client.Write(chunk + foff + aoff, data[doffset:doffset + ava])
					doffset = doffset + ava
					print('offset:%s ava:%s' % (offset, ava))
				dlen = dlen - ava
				# increment offset further
				offset = offset + ava
			
			if dlen < 1:
				break
			
			#data = client.Read(chunk + foff, ava)
			#dlen = dlen - ava
			#out.append(data)
		
			# track our base offset (minus the header)
			boff = boff + (csize - foff)
			# switch to next chunk
			chunk = nchunk
			if chunk == 0:
				# exit even if not done reading
				break
			# header is only 16 bytes
			foff = 16
			# read next chunk and current chunk size
			nchunk, csize = struct.unpack('>QQ', client.Read(chunk, 16))
		if write is False:
			return b''.join(out)
		return dlen
	
	'''
		This will allocate a file. The file has no name. The return value is the
		file offset on the storage block. You need to write to the file to give
		it a name.
	'''
	def AllocateFile(self, size):
		client = self.client
		cs = self.cs
		
		chunks = cs.AllocChunksForSegment(size)
		
		if chunks is None:
			return None
		
		fchunk = chunks.pop()
		rchunk = fchunk
		
		fheader = True
		
		rootfileoff = struct.unpack('>Q', client.Read(self.metabase, 8))[0]
		
		tlen = 0
		lchunk = None
		while True:
			# write the next link on the previous chunk
			if lchunk is not None:
				client.Write(lchunk[0] + hoff, struct.pack('>Q', fchunk[0]))
		
			# write chunk header
			if fheader:
				print('fchunk[0]:%x' % fchunk[0])
				client.Write(fchunk[0], struct.pack('>QQQQH', rootfileoff, 0, fchunk[1], size, 0))
				hoff = 8
				tlen = tlen + (fchunk[1] - (8 * 4 + 2))
			else:
				client.Write(fchunk[0], '>QQ', 0, fchunk[1])
				hoff = 0
				tlen = tlen + (fchunk[1] - (8 * 2))
			lchunk = fchunk
			
			# exit out no more chunks
			if len(chunks) < 1:
				break
			# get next chunk
			fchunk = chunks.pop()
		# do we need one more page?
		# TODO: this might have to handle cases where we
		#       need more than one 4096 or something bigger
		if tlen < size:
			assert(tlen < 4096)
			# try a 4096 byte one
			fchunk = cs.PullChunk(0)
			if fchunk is None:
				# push all other chunks back onto stacks
				for chunk in chunks:
					# push chunk back into free chunk buckets
					cs.PushChunk(chunk[2], chunk[0])
				return None
			# link to last chunk
			client.Write(lchunk[0] + hoff, struct.pack('>Q', fchunk[0]))
			# make header for this new chunk
			client.Write(fchunk[0], struct.pack('>QQ', 0, fchunk[1]))

		# link it into the file system now that it is done
		client.Write(self.metabase, struct.pack('>Q', rchunk[0]))
		return rchunk[0]
	
	def UnitTest(self):
		client = self.client
		cs = self.cs
	
		self.Format()
		
		client.SetCommunicationExceptionTime(45)
		client.SetRelinkTimeout(15)

		files = []
		
		random.seed(93820192)
		
		while True:
			# decide what to do
			op = random.randint(0, 0)
			print('op:%s' % op)
			
			# verify all files and content
			if True:
				bad = False
				for file in files:
					f = file[0]
					fsz = file[1]
					fname = file[2]
					fdata = file[3]
					#print('verifying:[%s] fsz:%s' % (fname, fsz))
					_data = self.ReadFile(f, 0, fsz)
					if True and _data != fdata:
						print('OUCH')
						print('fsz:%s' % fsz)
						print('f:%x' % f)
						print(len(fdata), fdata)
						print(len(_data), _data)	
						bad = True
				if bad:
					raise Exception('file data not correct')
			
			
			# make new file
			if op == 0:
				# random name
				name = IDGen.gen(4)
				# random size (between 10 bytes and a little over 1MB)
				fsz = random.randint(len(name) + 10, len(name) + 20)
				f = self.CreateFile(name, fsz)
				
				print('created:[%s] f:%x' % (name, f))
				# make sure f is not already used
				for file in files:
					if f == file[0]:
						print('dup:%x' % f)
						raise Exception('faddr duplicate')
				print('		created')
				if f is not None:
					afsz = fsz - len(name) - 5
					data = IDGen.gen(afsz)
					print('		writing:[%s]' % data)
					self.WriteFile(f, 0, data)
					files.append((f, afsz, name, data))
					print('		done writing')
				else:
					# we need to delete a file
					raise Exception('out of memory')
			
		#cs.TestSegmentAllocationAndFree()
		
		list = fs.EnumerateFileList()
		
		#fs.TruncateFile(list[0][1], 4096 * 5)
		
		fs.EnumerateFileList()
		
		fs.TruncateFile(list[0][1], 8192)
		
		data = IDGen.gen(8192)
		
		fs.WriteFile(list[0][1], 0, data)
		_data = fs.ReadFile(list[0][1], 0, 16000)
		
		print('_data-len:%s' % len(_data))
		
		if _data != data:
			print('OOPS')
			exit()
		
		
		list = fs.EnumerateFileList()
		print(list)
