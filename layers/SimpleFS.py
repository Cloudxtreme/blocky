import layers.interface
import struct

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
			print('@@@ reading header:%x' % cur)
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
	def WriteFileFromMemory(self, foff, data, off = 0):
		raise Exception('Not Implement')
	def __PushChunksInChain(self, chunk):
		bpsz = self.GetBasePageSize()
		client = self.client
		cs = self.cs
		while chunk != 0:
			nchunk, size = struct.unpack('>QQ', client.Read(chunk, 16))
			
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
		while chunk != 0:
			tsize = tsize + (csize - hoff)
			dlen = dlen - (csize - hoff)
			
			# we are going to have to make it smaller
			if tsize > newsize:
				if nchunk != 0:
					# okay, there is no need for another chunk so
					# we can drop the next chunk and any others
					cs.__PushChunksInChain(nchunk)
				# now let us evaluate if this current change 
				# can be made smaller and still contain the
				# data
				bpsz = cs.GetBasePageSize()
				level = (csize / bpsz) - 1
				while level > -1:
					if bpsz << level < dlen:
						# take previous level
						level = level + 1
						break
					level = level - 1
				
				if level != (csize / bpsz) - 1:
					# allocate new chunk that is smaller for data
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
			
			for chunk in chunks:
				# write header to point to this chunk we are adding
				next, csize = struct.unpack('>QQ', client.Read(_chunk, 16))
				client.Write(_chunk, struct.pack('>QQ', chunk[0], csize))
				# write header for this chunk
				client.Write(chunk, struct.pack('>QQ', 0, chunk[1]))
				# set last chunk to this chunk
				_chunk = chunk
				# now loop will grab next chunk
				
		# exit we are done
		return True
		
	def ReadFileIntoMemory(self, foff, offset = 0, length = None):
		client = self.client
		out = []
		chunk = foff
		next, nchunk, csize, dlen, nlen = struct.unpack('>QQQQH', client.Read(foff, 8 * 4 + 2))
		foff = 8 * 4 + 2
		while dlen > 0:
			# process this chunk
			ava = csize - foff
			
			if ava > dlen:
				ava = dlen
			
			data = client.Read(chunk + foff, ava)
			dlen = dlen - ava
		
			out.append(data)
		
			# get next chunk
			chunk = nchunk
			foff = 16
			nchunk, csize = struct.unpack('>QQ', client.Read(chunk, 16))
		return b''.join(data)
	def WriteNewFileFromMemory(self, rpath, data):
		client = self.client
		cs = self.cs
		
		chunks = cs.AllocChunksForSegment(len(data) + len(rpath))
		
		# [(offset, size, level), ...]
		fchunk = chunks.pop()
		rchunk = fchunk

		f = struct.unpack('>Q', client.Read(self.metabase, 8))[0]
		
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
				client.Write(fchunk[0], struct.pack('>QQQQH', f, nchunk[0], fchunk[1], len(data), len(rpath)))
				hdrlen = 8 * 4 + 2
				nextoff = 8
			else:
				# next chunk in this file, this chunk size
				client.Write(fchunk[0], struct.pack('>QQ', nchunk[0], fchunk[1]))
				hdrlen = 8 * 2
				nextoff = 0
				
			if doff < len(wdata):
				# write some file data
				crem = fchunk[1] - hdrlen
				if crem > len(wdata):
					crem = len(wdata) - doff
				print('writing %s bytes of data out of %s' % (crem, len(wdata)))
				client.Write(fchunk[0] + hdrlen, wdata[doff:doff + crem])
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
			client.Write(fchunk[0] + nextoff, struct.pack('>Q', chunk[0]))
			# write our header
			client.Write(chunk[0], struct.pack('>QQ', 0, chunk[1]))
			off = 8 * 2
			# write remaining data
			client.Write(chunk[0] + off, data[doff:])
		
		print('wrote [%s] to root' % rpath)
		client.Write(self.metabase, struct.pack('>Q', rchunk[0]))
