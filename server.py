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
import traceback
import mmap
import pprint
import signal

from misc import *

'''
	For testing I just import the client directly into this module!
'''
#from client import *
	
class TooManyVectorsException(Exception):
	pass
class BadHashException(Exception):
	pass
class InvalidLinkIDException(Exception):
	pass
class AddrNotInLinkException(Exception):
	pass
class VectorAlreadyUsedException(Exception):
	pass
class UnknownMessageTypeException(Exception):
	pass
	
critical = {
	'inside':		False,
	'exit':			False
}
	
def HandleSIGINT(signal, frame):
	global		critical
	
	if critical['inside'] is False:
		sys.exit(0)
	# if we are inside a critical section then just ignore it
	print('SIGINT: inside critical section')
	# schedule us to exit once we exit the critical section
	critical['exit'] = True
	
def CriticalEnter():
	global		critical
	critical['inside'] = True
	
def CriticalExit():
	global		critical
	critical['inside'] = False
	if critical['exit'] is True:
		sys.exit(0)
	
'''
	This will create a server and block.
'''
def server(lip, lport):
	# generate unique ids of length (hard coded in other parts of code)
	uidgen = IDGen(4)
	
	links = {}
	
	blocks = {}
	
	
	bytesin = 0
	bytestime = time.time()
	
	'''
		This is my testing block. Normally, the block meta-data
		is loaded from the disk on a block connection request. But,
		for testing I preload this one. It however can be removed
		after some time of idle, but for most of my tests it wont
		really ever go idle for now....
	'''
	'''
	blocks[b'ekwL#i293828eeMDj43EKowi49382dko39#KMekoe993824'] = {
		'fd':		None,
		'path':		'/home/kmcguire/block.test',
		'size':		1024 * 1024 * 500,
		'ref':		0,
		'id':		b'ekwL#i293828eeMDj43EKowi49382dko39#KMekoe993824',
		'lmt':		0,
		'locks':	{}
	}
	'''
	
	'''
		Basically, I have to do this for the cricial section which
		is currently used around the writes for the DoWriteHold
		operation. The client expects those writes to either happen
		or not happen, and since I would like to be able to shutdown
		the server with ctrl+c this kinda makes that possible by giving
		enough time to complete the writes then exit.
	'''
	signal.signal(signal.SIGINT, HandleSIGINT)
	
	if os.path.exists('pubkey') and os.path.exists('prikey'):
		print('[server] loading public and private key pair')
		fd = open('pubkey', 'rb')
		keypub = fd.read()
		fd.close()
		fd = open('prikey', 'rb')
		keypri = fd.read()
		fd.close()
		keypub = pubcrypt.toi256(keypub)
		keypri = pubcrypt.toi256(keypri)
	else:
		print('[server] generating public and private key pair')
		keypub, keypri = pubcrypt.keygen(2 ** 64)
		fd = open('pubkey', 'wb')
		fd.write(pubcrypt.fromi256(keypub))
		fd.close()
		fd = open('prikey', 'wb')
		fd.write(pubcrypt.fromi256(keypri))
		fd.close()	
		print('[server] done generating key pair')
		
	sock =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((lip, lport))
	
	
	wta = 0
	wtc = 0
	wtlr = 0
	
	llic = time.time()
	lbuc = time.time()
	while True:
		# ----------------- IDLE LINKS ---------------
		# go through and drop any links that have been
		# idle for specific amount of time or greater
		if time.time() - llic > (60 * 5):
			llic = time.time()
			_toremove = []
			for addr in links:
				for uid in links[addr]:
					link = links[addr][uid]
					if time.time() - link['lmt'] > (60 * 1):
						# see if we can drop the block that
						# may be opened
						block = link['block']
						if block is not None:
							# decrement the block ref
							block['ref'] = block['ref'] - 1
							if block['ref'] < 1:
								if block['fd'] is not None:
									# close the file handle
									block['fd'].close()
								# drop the block from memory
								bid = block['id']
								if bid in blocks:
									del blocks[bid]
									print('dropped block [%s]' % bid)
									# we can not store the mmap object
									block['mm'] = None
									# should be better setting this to zero
									block['lmt'] = 0
									# write updated block info to disk
									fd = open('block.%s' % bid, 'w')
									pprint.pprint(block, fd)
									fd.close()
									
									
						# drop the link
						#del links[addr][uid]
						_toremove.append((addr, uid))
			for e in _toremove:
				del links[e[0]][e[1]]
				if len(links[e[0]]) < 1:
					del links[e[0]]
					print('dropping link %s:%s' % (e[0], e[1]))
	
		# --------------- UPDATED BLOCKS ----------------
		# go through and look for blocks which have been updated
		# but are currently loaded into memory (well block meta-data)
		# this can happen when the customer has changed the size
		# of the block
		if time.time() - lbuc > (60 * 5):
			lbuc = time.time()
			for bid in blocks:
				block = blocks[bid]
				if os.path.getmtime(block['path']) > block['lmt']:
					# just ignore it
					if os.path.exists('block.%s' % bid) is False:
						continue
					# reload the block meta-data from disk
					fd = open('block.%s' % bid, 'r')
					_block = eval(fd.read())
					fd.close()
					# the only thing that can currently change is
					# the block size, so lets only update that
					# because there could be other fields attached
					# to this block that we wish to preserve
					block['size'] = _block['size']
	
		# ----------------- PACKET HANDLING -------------------
		sock.settimeout(0.1)
		
		for addr in links:
			for lid in links[addr]:
				link = links[addr][lid]
				outgoing = link['outgoing']
				for vector in outgoing:
					out = outgoing[vector]
					#vector = out[0]		# vector (redundant)
					lsend = out[1]			# last send time
					edata = out[2]			# encrypted data

					if time.time() - lsend > 5:
						# remote client will send a ACK packet
						# saying that they have recieved this
						# packet which will remove it from the
						# outgoing list
						if lsend > 0:
							#print('RESEND vector:%s' % vector)
							print('*', end='')
						outgoing[vector] = (vector, time.time(), edata)
						sock.sendto(edata, link['addr'])
		
		st = time.time()
		try:
			data, addr = sock.recvfrom(0xffff)
			
			bytesin = bytesin + len(data)
			
		except socket.timeout as e:
			continue
			
		wt = time.time() - st
		
		wta = wta + wt
		wtc = wtc + 1
		
		if time.time() - wtlr > 5:
			wtlr = time.time()
			print('wait time average %s' % (wta / wtc))
			tt = time.time() - bytestime
			print('input KB/second is %s' % ((bytesin / tt) / 1024))
		
		# it should actually be faster in a lot of cases
		# to just catch the exception rather than check
		# data bounds and such things; the only problem
		# is making sure the system is still stable if an
		# exception does occur; all exceptions are logged
		# to disk with the source IP and port for easier
		# diagnostics...
		try:
			# TODO: at some point we need to drop links that have timed out
			type = struct.unpack_from('>B', data)[0]
			
			# they want our public key
			if type == PktCodeClient.GetPublicKey:
				# convert key from integer into string of data
				nid = struct.unpack_from('>I', data[1:5])[0]
				data = pubcrypt.fromi256(keypub)
				data = struct.pack('>BI', PktCodeServer.PublicKey, nid) + data
				sock.sendto(data, addr)
				continue
				
			# they wish to setup the encryption between us
			if type == PktCodeClient.SetupEncryption:
				# the data has been encrypted using the public key
				data = data[1:]
				nid = struct.unpack('>I', data[0:4])[0]
				data = data[4:]
				# decrypt it and reveal the encryption key
				data = pubcrypt.decrypt(data, keypri, keypub)
				# create a unique link
				if addr not in links:
					links[addr] = {}
				# if too many connections from the same IP then
				# just ignore another one; i should make it send
				# a message to alert the client that this has
				# happened
				if len(links[addr]) > 20:
					continue
				# generate unique link ID
				uid = uidgen.ugen()
				links[addr][uid] = {
					'crypter':		SymCrypt(data),
					'addr':			addr,
					'ulid':			uid,
					'vman':			VectorMan(),		
					'lmt':			time.time(),			# last message time
					'block':		None,
					'locks':		[],
					'wholds':		[],						# write holds
					'outgoing':		{},						# outgoing packets
				}
				print('established link')
				# build the reply
				data = struct.pack('>BI', PktCodeServer.EstablishLink, nid) + uid
				# send the reply over the network
				sock.sendto(data, addr)
				continue
			# encrypted message
			if type == PktCodeClient.EncryptedMessage:
				# get the unique link id
				data = data[1:]
				uid = data[0:4]
				data = data[4:]
				# find their link, or ignore it
				if addr not in links:
					# let them know
					data = struct.pack('>B', PktCodeServer.NoLink)
					sock.sendto(data, addr)
					raise AddrNotInLinkException()
				if uid not in links[addr]:
					# let them know
					data = struct.pack('>B', PktCodeServer.NoLink)
					sock.sendto(data, addr)
					raise InvalidLinkIDException()
				link = links[addr][uid]
	
				link['lmt'] = time.time()
				# [type][uid][hash][vector][data]
				# hash data before encryption
				# encrypt hash and data
				
				# we apparently have a valid link, now decrypt the remaining data
				data = link['crypter'].decrypt(data)
				
				# get hash (sha-512)
				hash = data[0:64]
				# compute current hash
				m = hashlib.sha512()
				# drop hash so we can compute with out it
				data = data[64:]
				m.update(data)
				_hash = m.digest()
				if _hash != hash:
					# this helps to make logging this problem easier
					# and could show when someone is messing around, but
					# because of the openess of the client this will
					# be expected, so I might disable this problem 
					print('#', end='')
				# get vector
				'''
					the vector prevents replay attacks where the attacker
					will just resend the exact same message, so to keep that
					from happening we make vectors we get invalid so if they
					are sent twice they are simply ignored and this also helps
					prevent re-transmissions from having effects twice so
					it serves a dual purpose
				'''				
				vector = struct.unpack_from('>Q', data)[0]
				
				# remove vector from data sequence
				data = data[8:]
				# get type
				type = data[0]
				# remove type from data sequence
				data = data[1:]

				# we do not verify vectors for acknowledgements as a replay attack
				# can only occur after the attacker has sniffed the packet and if
				# so getting a duplicate ack will not do anything because that vector
				# will never be used again for the life of this link
				if type == PktCodeClient.Ack:
					_vector = struct.unpack_from('>Q', data)[0]
					# remove vector from outgoing
					#print('GOT ACK FOR vector:%s' % _vector)
					if _vector in link['outgoing']:
						#print('@@@@@@@@@@@@@IN OUTGOING')
						del link['outgoing'][_vector]
					# no reply needed
					continue
				
				# try to keep us from being DoS'ed by someone
				# just creating as many vectors as possible 
				# causing VectorMan to eat crazy amounts of
				# memory; just throw an exception to escape
				# as it is the easiest way to get out of this
				# code block; we also just ignore vectors that
				# have already been used because sometimes they
				# are resends
				if link['vman'].IsVectorGood(vector, 300) is False:
					# this means the vector could not be added to
					# the existing ranges AND it could not be added
					# as a single because we have hit our max range
					# limit
					print('.', end='')
					continue
				
				#if vector == 117:
					#print('GOT VECTOR 117')
					#while True:
					#	pass
				
				# they wish to connect to a block
				if type == PktCodeClient.BlockConnect:
					# they wish to connect with a block which will
					# give them access to the block if the supplied
					# credentials are correct
					#
					# TODO: add somekind of timeout here to prevent brute forcing
					#
					print('block connect')
					nid = struct.unpack_from('>I', data)[0]
					data = data[4:]
					bid = data
					if bid not in blocks:
						bid = bid.decode('utf8', 'ignore')
						# see if we load the block into memory from disk
						bpath = 'block.%s' % bid
						
						# this is just temporary for demoing the server
						if os.path.exists(bpath) is False:
							# create it! (for demoing the service)
							block = {
									'fd':		None,
									'path':		'<replaceme>',
									'size':		1024 * 1024 * 50,
									'ref':		0,
									'maxref':	10,
									'lmt':		0,
									'locks':	{},
									'mm':		None					
							}
							fd = open(bpath, 'w')
							pprint.pprint(block, fd)
							fd.close()
						
						if os.path.exists(bpath):
							fd = open(bpath, 'r')
							block = eval(fd.read())
							fd.close()
							blocks[bid] = block
							# get last modified time so we can tell if we
							# need to reload a block's meta data from disk
							# such as when the size has been changed
							block['lmt'] = os.path.getmtime(bpath)
							block['path'] = '/home/kmcguire/block.%s' % (bid)
							print('path:%s' % block['path'])
						else:
							print('block file [%s] does not exist' % bpath)
							# tell them they failed
							data = struct.pack('>BI', PktCodeServer.BlockConnectFailure, nid)
							data, _vector = BuildEncryptedMessage(link, data)
							link['outgoing'][_tmp] = (_tmp, 0, data)
							continue
					# they connected, so open the block if it is not open already
					link['block'] = blocks[bid]
					block = blocks[bid]
					block['id'] = bid
					
					if block['ref'] > block['maxref']:
						data, _tmp = BuildEncryptedMessage(link, struct.pack('>BI', PktCodeServer.BlockConnectFailure, nid))
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue				
					
					block['ref'] = block['ref'] + 1
					
					if block['fd'] is None:
						# either create the file and allocate it's full size
						# or open an existing and change it's size either to
						# be smaller or larger (whatever is specified in block)
						if os.path.exists(block['path']) is False:
							f = open(block['path'], 'w')
							f.truncate(block['size'])
							f.close()
						else:
							f = open(block['path'], 'r+')
							f.truncate(block['size'])
							f.close()
						ofd = os.open(block['path'], os.O_RDWR)
						#f = open(block['path'], 'r+')
						#access = mmap.ACCESS_WRITE
						block['mm'] = mmap.mmap(ofd, block['size'])
					data, _tmp = BuildEncryptedMessage(link, struct.pack('>BI', PktCodeServer.BlockConnectSuccess, nid))
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				# go ahead and get the block and fd ready
				block = link['block']
				
				# link *must* be connected to a block; this also prevents someone
				# from making a lot of connects and just flooding our memory
				# with locks; i already have a limit to the maximum number of locks
				# so this prevents that
				if block is None:
					data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue					
				
				#fd = block['fd']
				mm = block['mm']
				
				if type == PktCodeClient.WriteHold:
					offset = struct.unpack_from('>Q', data)[0]
					data = data[8:]
					if offset + len(data) >= block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						print('past end of buffer')
						continue
					
					# prevent DoS by limiting the number of write holds
					if len(link['wholds']) > 50:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						print('too many holds')
						continue
					
					link['wholds'].append((offset, data))
					
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, offset, len(data))
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue	
			
				if type == PktCodeClient.FlushWriteHold:
					# flush them if any
					link['wholds'] = []
					data = struct.pack('>BQ', PktCodeServer.FlushWriteHold, vector)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue						
			
				# lets the client verify all write are holding
				if type == PktCodeClient.GetWriteHoldCount:
					data = struct.pack('>BQQ', PktCodeServer.GetWriteHoldCount, vector, len(link['wholds']))
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				
				# very critical section
				if type == PktCodeClient.DoWriteHold:
					# all these writes need to happen, or else we fail
					# our contract with the client and risk their data
					# being in a corrupt state
					CriticalEnter()
					for hold in link['wholds']:
						mm.seek(hold[0])
						mm.write(hold[1])
					CriticalExit()
					# clear write holds
					link['wholds'] = []
					
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, offset, len(data))
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
					
				if type == PktCodeClient.Write:
					offset = struct.unpack_from('>Q', data)[0]
					data = data[8:]
					if offset + len(data) >= block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue				
					#fd.seek(offset)
					#fd.write(data)
					mm.seek(offset)
					mm.write(data)
					
					#print('write offset:%x data-len:%x' % (offset, len(data)))
					
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, offset, len(data))
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.WriteAddLoop:
					offset, jump, count = struct.unpack_from('>QQQ', data)
					data = data[8*3:]
					# auto-fail this; at the moment I am disabling it because it could be used
					# to DoS the server either intentionally and by accident.. if i find out i
					# need it i can always re-enable it but i am leaving all the support code in
					# place for it incase i do need it
					if True or offset + (jump * (count - 1)) + len(data) >= block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue
					print('server write count:%s' % count)
					y = 0
					'''
					for x in range(0, count):
						_offset = offset + (x * jump)
						fd.seek(_offset)
						fd.write(data)
						#if y > 13000:
						#	print('offset:%s' % _offset)
						#	fd.close()
						#	block['fd'] = open(block['path'], 'r+b', 1024 * 1024 * 100)
						#	fd = block['fd']
						#	y = 0
						#y = y + 1
						print('x:%s offset:%s' % (x, _offset))
					print('server done')
					'''
					
					mm = block['mm']
					
					print('server write start')
					for x in range(0, count):
						_offset = offset + (x * jump)
						mm.seek(_offset)
						mm.write(data)
					mm.flush()
					print('server write end')
					
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, offset, len(data))
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.Read:
					offset, length = struct.unpack_from('>QH', data)
					if offset + length >= block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue
					#fd.seek(offset)
					mm.seek(offset)
					#_data = fd.read(length)
					_data = mm.read(length)
					data = struct.pack('>BQQH', PktCodeServer.ReadSuccess, vector, offset, length) + _data
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.Exchange8:
					offset, newvalue = struct.unpack_from('>QB', data)
					if offset >= block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue
					#fd.seek(offset)
					#oldval = fd.read(1)
					#fd.seek(offset)
					#fd.write(newvalue)
					mm.seek(offset)
					oldval = mm.red(1)
					mm.seek(offset)
					mm.write(newvalue)
					data = struct.pack('>BQQB', PktCodeClient.Exchange8Success, vector, offset, oldval)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.BlockLock:
					offset = struct.unpack_from('>Q', data)
					data = data[16:]
					if offset + length >= block['size'] or len(link['locks']) > 20:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue
					
					link['locks'].append((offset, data))
					
					data = struct.pack('>BQQQ', PktCodeServer.LockSuccess, vector, offset, length)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.BlockSize:
					data = struct.pack('>BQQ', PktCodeServer.BlockSizeReply, vector, block['size'])
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.BlockUnlock:
					offset = struct.unpack_from('>Q', data)
					
					# remove the lock specified
					_locks = []
					for lock in link['locks']:
						if lock[0] != offset:
							_locks.append(lock)
					link['locks'] = _locks
					
					data = struct.pack('>BQQB', PktCodeServer.UnlockSuccess, vector, offset, force)
					data, _tmp = BuildEncryptedMessage(link, data)[0]
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
			print('unknown message type:%s' % type)
			raise UnknownMessageTypeException()
			# end-of-encrypted-message-block
		except Exception:
			traceback.print_exc(file = sys.stdout)
			# log all exceptions to disk so they can be reviewed
			if os.path.exists('exceptions'):
				fd = open('exceptions', 'r+')
			else:
				fd = open('exceptions', 'w')
			fd.write('-------- %s --------\n' % (addr, ))
			traceback.print_exc(file = fd)
			fd.write('-------- EOE -------\n')
			fd.close()
		# end-of-main-while-loop
	
	# sock.sendto(data, (ip, port))
	# data, addr = sock.recvfrom(max)	
	
#thread = threading.Thread(target = doClient)
#thread.start()
	
server('0.0.0.0', 1874)

'''
ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ss.bind(('0.0.0.0', 8888))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

rip = '127.0.0.1'
rport = 8888
rip = socket.gethostbyname(rip)
#rip = socket.inet_aton(rip)
#print(type(rip))
#exit()
sock.bind(('0.0.0.0', 0))
saddr = (rip, rport)
sock.connect(saddr)

st = time.time()
m = 40000
for x in range(0, m):
	sock.send(bytes((1, 2, 3, 4)))
	#sock.sendto(bytes((1, 2, 3, 4)), saddr)
	
print('tt:%s tps:%s' % (time.time() - st, m / (time.time() - st)))
exit()
'''