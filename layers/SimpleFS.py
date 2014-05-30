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
			print('	pushed %x:%s' % (cur, csize))
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
			
			print('		pushing chunk:%x size:%x' % (chunk, size))
			
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
					
					# write the 5th field of the master header to show new size
					client.Write(foff + 8 * 4, struct.pack('>Q', newsize))
					
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
		print('dlen:%s nlen:%s' % (dlen, nlen))
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
		
		print('__RWFileMemory Start')
		
		# unless they specify None move them past the name string
		if offset is not None:
			offset = nlen + offset
		else:
			offset = 0
			
		if write is True:
			dlen = len(data)
		else:
			dlen = length
		boff = nlen
		doffset = 0
		while True:
			# are we current on a chunk where our offset begins
			print('	boff:%x csize:%x foff:%x (csize-foff):%x offset:%x' % (boff, csize, foff, csize - foff, offset))
			if boff + (csize - foff) >= offset:
				# we our offset from base of chunk
				aoff = offset - boff
				
				# the most we can read or write on this chunk
				print('	csize:%x aoff:%x foff:%x' % (csize, aoff, foff))
				ava = csize - (aoff + foff)
				print('	ava:%x' % ava)
				if ava > dlen:
					# if its more than we need then adjust
					ava = dlen
				print('	ava:%x' % ava)
				# yes, let us read what we can or need
				if write is False:
					print('	reading ava:%x' % ava)
					out.append(client.Read(chunk + foff + aoff, ava))
				else:
					cbsz = client.GetBlockSize()
					print('	ava:%x' % ava)
					print('	writing... cbsz:%x offset:%x ava:%x' % (cbsz, chunk + foff + aoff, ava))
					print('	ava:%x' % ava)
					client.Write(chunk + foff + aoff, data[doffset:doffset + ava])
					doffset = doffset + ava
					print('offset:%s ava:%s' % (offset, ava))
				dlen = dlen - ava
				# increment offset further
				offset = offset + ava
				
			if dlen < 1:
				print('READ DLEN:%s < 1' % dlen)
				break
			
			#data = client.Read(chunk + foff, ava)
			#dlen = dlen - ava
			#out.append(data)
		
			# track our base offset (minus the header)
			boff = boff + (csize - foff)
			print('	get next chunk')
			# switch to next chunk
			if nchunk == 0:
				print('		exit nchunk was zero')
				# exit even if not done reading/writing
				break
			chunk = nchunk
			# header is only 16 bytes
			# read next chunk and current chunk size
			nchunk, csize = struct.unpack('>QQ', client.Read(chunk, 16))
			# figure out who last wrote this csize
			
			if csize == 0:
				client.DebugPrintWhoWrote(chunk + 8, 8)
			
			toff = chunk + 8
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
				print('		writing backwards link')
				client.Write(lchunk[0] + hoff, struct.pack('>Q', fchunk[0]))
			
			assert(fchunk[1] > 4000)
			# write chunk header
			if fheader:
				fheader = False
				print('fchunk[0]:%x' % fchunk[0])
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
				print('no more chunks; exiting tlen:%x size:%x' % (tlen, size))
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
			print('op:%s' % op)
			
			if len(files) < 1:
				op = 0
			if len(files) > 100:
				op = 1
			
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
						print(len(fdata), fdata[0:20])
						print(len(_data), _data[0:20])	
						bad = True
				if bad:
					raise Exception('file data not correct')
			
			# delete file
			if op == 1:
				i = random.randint(0, len(files) - 1)
				file = files[i]
				print('deleting file %s' % file[2])
				self.DeleteFile(file[0])
				files.pop(i)
				continue
			
			# make new file
			if op == 0:
				# random name
				name = IDGen.gen(4)
				# random size (between 10 bytes and a little over 1MB)
				fsz = random.randint(len(name) + 10, len(name) + 8192)
				f = self.CreateFile(name, fsz)
				
				print('created:[%s] f:%x' % (name, f))
				# make sure f is not already used
				if True:
					for file in files:
						if f == file[0]:
							print('dup:%x' % f)
							raise Exception('faddr duplicate')
					print('		created')
				if f is not None:
					afsz = fsz - len(name) - 5
					data = IDGen.gen(afsz)
					print('		writing:[%s...]' % data[0:5])
					self.WriteFile(f, 0, data)
					files.append((f, afsz, name, data))
					print('		done writing')
				else:
					# we need to delete a file
					raise Exception('out of memory')
				continue
			# end-of-while-loop
			
		#cs.TestSegmentAllocationAndFree()
		list = fs.EnumerateFileList()
		fs.TruncateFile(list[0][1], 8192)
		# end-of-function