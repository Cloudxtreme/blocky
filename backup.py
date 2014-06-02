import os
import sys
import argparse
from layers.SimpleFS import SimpleFS
from layers.ChunkPushPullSystem import ChunkPushPullSystem
from client import Client

class FileInfo:
	def __init__(self, ptr, path, length, mtime):
		self.ptr = ptr
		self.path = path
		self.length = length
		self.mtime = mtime

class DifferentFormatException(Exception):
	pass
	
class UnableToLockException(Exception):
	pass

class SimpleBackup:
	def __init__(path, rhost, rport, bid):
		self.path = path		

		self.client = Client(rhost, rport, bytes(bid, 'utf8'))		
		self.client.SetLinkDropHandler(lambda : SimpleBackup.LinkDrop(self))
		self.cs = ChunkPushPullSystem(client, load = False)
		self.ValidCheck()
		
	def LinkDrop(self):
		pass
		
	def ValidCheck(self):
		if self.cs.IsFormatted() is False:
			self.valid = False
		self.fs = SimpleFS(cs)
		if self.fs.IsFormatted() is False:
			self.valid = False
		self.files = None
		self.lastvalid = 0
		
	def TryLock(self):
		if self.client.fs.TryLock() is False:
			raise UnableToLockException()
			
	def ValidRaise(self):
		# is the remote block valid?
		if self.valid is False:
			raise DifferentFormatException()
		# try to lock the remote block
		self.TryLock()
		# ensure listing has been created and recreate the listing
		# if the last call to one this function is older than
		# 30 seconds.. meaning we may have been link dropped which
		# means our global block lock has likely been released
		if self.files is None or time.time() - self.lastvalid > 30:
			# enumerate file listing
			self.files = self.EnumerateFiles()
		
	def PushFileFromMemory(self, lpath, prefix):
		self.ValidRaise()
		
	def PullFileIntoMemory(self, rpath):
		self.ValidRaise()
	'''
		This will enumerate all the files and produce a list which contains:
		
		0. [prefix].[path]
		1. [size]
		2. [mtime]
		3. [ptr]
	'''
	def EnumerateFiles(self):
		self.ValidRaise()
		
		fs = self.fs
		out = []
		flist = fs.EnumerateFileList()
		for finfo in flist:
			# grab additional information from meta-data
			# (metadata, ptr, length)
			mdata = finfo[0]
			fptr = finfo[1]
			flen = finfo[2]
			# parse meta-data
			nlen = struct.unpack_from('>H', mdata)
			# modification time
			mtime = struct.unpack_from('>Q', mdata, 2 + nlen)
			# store into structure and into list
			out.append(FileInfo(
				ptr = fptr,
				path = mdata[2:2 + nlen],
				length = flen,
				mtime = mtime
			))
		return out
		
	def Finish():
		self.client.Finish()
		
		'''
			This is a non-fatal exception, but it forces the developer
			to address the issue if it is not formatted before making
			any calls.
		'''
		if self.valid is False:
			raise DifferentFormatException()
	
	def IsFormatted(self):
		return self.valid
	'''
		Each layer needs to format the block.
	'''
	def Format(self):
		self.cs.Format(force = True)
		self.fs.Format(force = True)
		self.valid = True
		
	def Backup(self):
		pass
	
def main():
	args = argparse.ArgumentParser('backup.py')
	args.add_argument('--path', help='path to backup from')
	args.add_argument('--rhost', help='server hostname/IP/address', required=True)
	args.add_argument('--rport', help='server port', required=True)
	args.add_argument('--bid', help='server block ID', required=True)
	args.add_argument('-r', help='following into sub-directories', action='store_true')
	args = args.parse_args(sys.argv[1:])

	if args.path is not None:
		path = args.path
	else:
		path = os.getcwd()
	
	if args.r is True:
		print('recursion')
	
	bu = SimpleBackup(path, args.rhost, args.rport, args.bid)
	self.bu = bu
	
	bu.Backup()


main()