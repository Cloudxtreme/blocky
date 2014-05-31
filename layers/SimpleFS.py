import layers.interface
import struct
import random
import inspect
from misc import *

class SimpleFS(layers.interface.BasicFS):
	def __init__(self, cs):
		self.cs = cs
		self.client = cs.GetClient()
		self.metabase = 500
		
		self.dbgf = None
		
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
			next, prev, nchunk, tsize, dlen, nlen = struct.unpack('>QQQQQH', client.Read(cur, 8 * 5 + 2))
			# next file, next chunk, tchunksize, datalen, namelen
			# read file name
			off = cur + 8 * 4 + 2
			name = []
			while nlen > 0:
				# nlen = name length
				if nlen > tsize:
					clen = tsize
				else:
					clen = nlen
				nlen = nlen - clen
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
		cs = self.cs
		client = self.client
		
		root = struct.unpack('>Q', client.Read(self.metabase, 8))[0]
		next, prev, nchunk, csize, dlen, nlen = struct.unpack('>QQQQQH', client.Read(foff, 8 * 5 + 2))
		# set next for our prev
		if prev != 0:
			client.Write(prev, struct.pack('>Q', next))
		# set prev for our next
		if next != 0:
			client.Write(next + 8, struct.pack('>Q', prev))
		# set root if needs to be changed
		if foff == root:
			# set to prev if exists or next
			if prev != 0:
				client.Write(self.metabase, struct.pack('>Q', prev))
			else:
				client.Write(self.metabase, struct.pack('>Q', next))
		
		# now free pages used
		cur = foff
		while True:
			# free page
			cs.PushChunkBySize(csize, cur)
			# get next chunk
			if nchunk == 0:
				break
			cur = nchunk
			nchunk, csize = struct.unpack('>QQ', client.Read(cur, 8 * 2))
		# we are done!
		
	def __PushChunksInChain(self, chunk):
		cs = self.cs
		client = self.client
		
		bpsz = cs.GetBasePageSize()
		while chunk != 0:
			nchunk, size = struct.unpack('>QQ', client.Read(chunk, 16))
			
			# calculate level and push chunk back
			level = (size / bpsz) - 1
			
			cs.PushChunk(level, chunk)
			
			chunk = nchunk
	def TruncateFile(self, foff, newsize):
		client = self.client
		cs = self.cs
		next, prev, nchunk, csize, dlen, nlen = struct.unpack('>QQQQQH', client.Read(foff, 8 * 5 + 2))
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
					
					# write the 5th field of the master header to show new size
					client.Write(foff + 8 * 4, struct.pack('>Q', newsize))
					
					# exit we are done
					return True
			
			if nchunk == 0:				# if no more chunks then exit
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
			# write the new data size (5th field)
			client.Write(foff + 8 * 4, struct.pack('>Q', newsize))
		# exit we are done
		return True
	
	def SetNameLength(self, foff, nlen):
		client = self.client
		# get old sizes
		dlen, _nlen = struct.unpack('>QH', client.Read(foff + 8 * 4, 8 + 2))
		# restore bytes
		dlen = dlen + _nlen
		# subtract bytes
		dlen = dlen - nlen
		# write new sizes
		client.Write(foff + 8 * 4, struct.pack('>QH', dlen, nlen))
		
	def CreateFile(self, path, size):
		if type(path) is str:
			path = bytes(path, 'utf8')
		foff = self.AllocateFile(size + len(path))
		if foff is None:
			return None
		self.WriteFile(foff, None, path)
		self.SetNameLength(foff, len(path))
		return foff
		
	def GetNameLength(self, foff):
		client = self.client
		next, prev, nchunk, csize, dlen, nlen = struct.unpack('>QQQQQ', client.Read(foff, 8 * 5 + 2))
		return nlen
	
	def ReadFile(self, foff, offset, length):
		return self.__RWFileMemory(foff, length = length, offset = offset)
		
	def WriteFile(self, foff, offset, data):
		
		return self.__RWFileMemory(foff, offset = offset, data = data, write = True)
		
	def __RWFileMemory(self, foff, offset = 0, length = 0, data = None, write = False):
		client = self.client
		out = []
		chunk = foff
		next, prev, nchunk, csize, dlen, nlen = struct.unpack('>QQQQQH', client.Read(foff, 8 * 5 + 2))
		foff = 8 * 5 + 2
		
		# debugging code
		#if self.dbgf is None:
		#	self.dbgf = open('tmp', 'r+b')
		#	self.dbgf.truncate(1024 * 1024 * 50)
		
		
		# unless they specify None move them past the name string
		if offset is not None:
			# move offset above the name bytes
			offset = nlen + offset
		else:
			# let offset start at the name bytes
			offset = 0
			
		# determine our total data to be read/written 
		if write is True:
			dlen = len(data)
		else:
			dlen = length
		
		# our base starts at 0
		boff = 0
		# easily keeps track of our offset into data if we are writing
		doffset = 0
		
		while True:
			# if true then we can start reading/writing
			if boff + (csize - foff) >= offset:
				# this is out offset inside this chunk
				aoff = offset - boff
				
				# the most we can read or write on this chunk
				ava = csize - (aoff + foff)
				# check if we need to read less
				if ava > dlen:
					# if we need to real less then read less
					ava = dlen
					
				# decide if this is a read or write operation
				if write is False:
					out.append(client.Read(chunk + foff + aoff, ava))
					#self.dbgf.seek(chunk + foff + aoff)
					#out.append(self.dbgf.read(ava))
				else:
					#self.dbgf.seek(chunk + foff + aoff)
					#self.dbgf.write(data[doffset:doffset + ava])
					client.Write(chunk + foff + aoff, data[doffset:doffset + ava])
					# i could use dlen, but this is much easier to understand
					doffset = doffset + ava
				# subtract what we read from the remaining
				dlen = dlen - ava
				# increment our offset by what we read
				offset = offset + ava
			
			# if no more data to read then exit
			if dlen < 1:
				break
					
			# track our base offset (minus the header)
			boff = boff + (csize - foff)
			# switch to next chunk
			if nchunk == 0:
				# exit even if not done reading/writing
				if dlen > 0:
					raise Exception('EXITED BEFORE FINISHED')
				break
			chunk = nchunk
			# read next chunk and current chunk size
			nchunk, csize = struct.unpack('>QQ', client.Read(chunk, 16))
			# adust the header size to 16 bytes
			foff = 16
			
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
		
		chunks = cs.AllocChunksForSegment(size, initialsub = 8 * 5 + 2, repeatsub = 8 * 2)
		
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
			
			assert(fchunk[1] > 4000)
			# write chunk header
			if fheader:
				fheader = False
				client.Write(fchunk[0], struct.pack('>QQQQQH', rootfileoff, 0, 0, fchunk[1], size, 0))
				hoff = 16
				tlen = tlen + (fchunk[1] - (8 * 5 + 2))
			else:
				client.Write(fchunk[0], struct.pack('>QQ', 0, fchunk[1]))
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
		#if tlen < size:
		while tlen < size:
			print('*********%x' % (size - tlen))
			time.sleep(3)
			# try a 4096 byte one
			fchunk = (cs.PullChunk(0), cs.base)
			tlen = tlen + cs.base
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
			# set last chunk to this chunk and get new chunk
			lchunk = fchunk
			hoff = 0
		
		'''
			the root item should not have a valid prev pointer, but in the
			event that it does lets try to grab it and basically fix it
			
			TODO: write some code to walk backwards and completely fix the
				  problem if it exists (may be more linked previously)
		'''
		# check if root item has a prev pointer
		if rootfileoff != 0:
			_next, _prev = struct.unpack('>QQ', client.Read(rootfileoff, 16))
			if _prev != 0:
				# set our prev point to that prev
				client.Write(rchunk[0] + 8, struct.pack('>Q', _prev))
		
		# set current root's prev pointer to newly created file
		client.Write(rootfileoff + 8, struct.pack('>Q', rchunk[0]))
		# set root pointer to newly allocated file
		client.Write(self.metabase, struct.pack('>Q', rchunk[0]))
		return rchunk[0]
	
	def UnitTest(self):
		client = self.client
		cs = self.cs
	
		self.Format()
		
		client.SetCommunicationExceptionTime(45)
		client.SetRelinkTimeout(15)

		'''
		data = IDGen.gen(1024 * 2)
		f = self.CreateFile('apple', len(data))
		self.WriteFile(f, 0, data)
		_data = self.ReadFile(f, 0, len(data))
		
		print(data[0:20])
		print(_data[0:20])
		
		if data != _data:
			print('no match')
		
		exit()
		'''
		
		files = []
		
		random.seed(93820192)
		
		while True:
			# decide what to do
			op = random.randint(0, 1)
			
			if len(files) < 1:
				op = 0
			#if len(files) > 20:
			#	print('too many files')
			#	time.sleep(3)
			#	op = 1
			
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
						x = 0
						while x < len(fdata):
							if _data[x] != fdata[x]:
								print(len(fdata), x, fdata[x - 10:x + 10])
								print(len(_data), x, _data[x - 10:x + 10])
								break
							x = x + 1
						bad = True
				if bad:
					raise Exception('file data not correct')
			
			# delete file
			if op == 1 and len(files) > 0:
				i = random.randint(0, len(files) - 1)
				file = files[i]
				print('deleting index:%s file:[%s]' % (i, file[2]))
				self.DeleteFile(file[0])
				_files = []
				for _file in files:
					if _file != file:
						_files.append(_file)
				files = _files
				continue
			
			# make new file
			if op == 0:
				# random name
				name = IDGen.gen(4)
				# random size (between 10 bytes and a little over 1MB)
				fsz = random.randint(len(name) + 10, len(name) + 1024)
				f = self.CreateFile(name, fsz)
				
				if f is None:
					continue
				
				print('created:[%s] f:%x' % (name, f))
				# make sure f is not already used
				if True:
					for file in files:
						if f == file[0]:
							print('dup:%x' % f)
							raise Exception('faddr duplicate')
				if f is not None:
					afsz = fsz - len(name) - 5
					data = IDGen.gen(afsz)
					self.WriteFile(f, 0, data)
					files.append((f, afsz, name, data))
				else:
					# we need to delete a file
					raise Exception('out of memory')
				continue
			# end-of-while-loop
			
		#cs.TestSegmentAllocationAndFree()
		list = fs.EnumerateFileList()
		fs.TruncateFile(list[0][1], 8192)
		# end-of-function