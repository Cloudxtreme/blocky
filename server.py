import socket
import struct
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

from lib.misc import *
from lib import pubcrypt
	
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
	
	if os.path.exists('sconfig.py') is False:
		print('ERROR: You must have a "sconfig.py" file with a valid configuration.')

	fd = open('sconfig.py', 'r')
	sconfig = eval(fd.read())
	fd.close()
	
	bytesin = 0
	bytestime = time.time()
	
	'''
		Basically, I have to do this for the cricial section which
		is currently used around the writes for the DoWriteHold
		operation. The client expects those writes to either happen
		or not happen, and since I would like to be able to shutdown
		the server with ctrl+c this kinda makes that possible by giving
		enough time to complete the writes then exit.
	'''
	#signal.signal(signal.SIGINT, HandleSIGINT)
	
	if os.path.exists('id_rsa') and os.path.exists('id_rsa.pub'):
		# use external key (from ssh-keygen)
		print('loading id_rsa and id_rsa.pub')
		# this contains the exponent and public key
		pub = pubcrypt.readSSHPublicKey('id_rsa.pub')
		# this contains the public key and private key
		pri = pubcrypt.readSSHPrivateKey('id_rsa')
		
		# pub[0] == exponent
		# pub[1] == public key
		# pri[0] == public key
		# pri[1] == private key
		
		'''
			Well, this is a big oops. You see I started converting between
			Python large integers and byte form with a little endian format, 
			but SSH keys are stored using a big endian. So here I am just
			converting from big-endian to little-endian.
			
			Now, you may ask WHY?? Well, I *finally* got the code working and
			I am tired of messing with it. So I am leaving it like this and
			hopefully one day I will go back in and fix this by making all
			my functions work with big endian...
			
			Anyway.. for gods sake it finally works!!! 
		'''
		keypub = (pubcrypt.fromi256(pubcrypt.toi256r(pub[0])), pubcrypt.fromi256(pubcrypt.toi256r(pub[1])))
		keypri = (pubcrypt.fromi256(pubcrypt.toi256r(pri[0])), pubcrypt.fromi256(pubcrypt.toi256r(pri[1])))
		
		#keypub = (pub[0], pub[1])
		#keypri = (pri[0], pri[1])
	else:
		'''
			This was mainly done just to get everything started. For real security
			you would likely wanted to use the ssh-keypath path (code block above).
			As the ssh-keygen tool can produce much more secure keys. This is just
			here for testing in the event you do not want to generate any keys.
		'''
		if os.path.exists('pubkey') is False or os.path.exists('prikey') is False:
			print('[server] generating public and private key pair')
			keypub, keypri = pubcrypt.keygen(2 ** sconfig['public-key-bits'])
			fd = open('pubkey', 'wb')
			fd.write(pubcrypt.fromi256(keypub))
			fd.close()
			fd = open('prikey', 'wb')
			fd.write(pubcrypt.fromi256(keypri))
			fd.close()
			print('[server] done generating key pair')
		print('[server] loading public and private key pair')
		fd = open('pubkey', 'rb')
		keypub = fd.read()
		fd.close()
		fd = open('prikey', 'rb')
		keypri = fd.read()
		fd.close()
		# put it in a form used by SSH stuff
		keypub = (pubcrypt.fromi256(65537), keypub)
		keypri = (keypri, keypub[1])
		
	#keypub = (keypub[1], keypub[0])
	#keypri = (keypri[1], keypri[0])
		
	#c = pubcrypt.crypt(b'hello world', keypub)
	#p = pubcrypt.decrypt(c, keypri)
	#print('p', p[0:5])
	
	#print(len(keypub[0]), len(keypub[1]))
	#print(len(keypri[0]), len(keypri[1]))
	
	#if keypri[1] == keypub[1]:
	#	print('MATCH')
	
	print('opening server socket..')
	sock =  socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((lip, lport))
	
	print('server is running..')
	
	wta = 0
	wtc = 0
	wtlr = 0
	pc = 0
	pcst = time.time()
	
	hdt = 0					# highest delta time (helps find long pauses)
	
	st = time.time()
	
	llic = time.time()
	lbuc = time.time()
	while True:
		# ----------------- IDLE LINKS ---------------
		# go through and drop any links that have been
		# idle for specific amount of time or greater
		if time.time() - llic > sconfig['link-idle-check']:
			llic = time.time()
			_toremove = []
			for addr in links:
				for uid in links[addr]:
					link = links[addr][uid]
					if time.time() - link['lmt'] > sconfig['link-idle-drop']:
						# see if we can drop the block that
						# may be opened
						block = link['block']
						if block is not None:
							# decrement the block ref
							block['ref'] = block['ref'] - 1
							print('block[%s][ref]:%s' % (block['id'], block['ref']))
							if block['ref'] < 1:
								# drop the block from memory
								bid = block['id']
								# delete it from the blocks list
								print('blocks', blocks)
								# TODO: fix this bug
								if bid in blocks:
									del blocks[bid]
								print('dropped block [%s]' % bid)
								# flush data to disk
								block['mm'].flush()
								# close the mmap 
								block['mm'].close()
								# close the OS file handler
								os.close(block['fd'])
								# we can not store mm so None it out
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
			# i do all the removal work outside of the
			# iteration because it can throw an exception
			# if i modify the list/dict while iterating
			# over it
			for e in _toremove:
				link = links[e[0]][e[1]]
				# execute unlocks
				block = link['block']
				if block is not None:
					mm = block['mm']
					print('unlocking locks for link')
					for lock in link['locks']:
						mm.seek(lock)
						mm.write(struct.pack('>II', 0, 0))
				uidgen.urem(e[1])				# free that id to be used again
				del links[e[0]][e[1]]			# remove from links
				# also remove addr entry if empty
				if len(links[e[0]]) < 1:
					del links[e[0]]
				# report the dropping of the link
				print('dropping link %s:%s' % (e[0], e[1]))
	
		# --------------- UPDATED BLOCKS ----------------
		# go through and look for blocks which have been updated
		# but are currently loaded into memory (well block meta-data)
		# this can happen when the customer has changed the size
		# of the block
		if time.time() - lbuc > sconfig['block-update-check']:
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

					if time.time() - lsend > sconfig['resend-delay']:
						# remote client will send a ACK packet
						# saying that they have recieved this
						# packet which will remove it from the
						# outgoing list
						if lsend > 0:
							#print('RESEND vector:%s' % vector)
							print('*', end='')
						outgoing[vector] = (vector, time.time(), edata)
						sock.sendto(edata, link['addr'])
		
		dt = time.time() - st
		if dt > hdt:
			hdt = dt
		
		
		st = time.time()
		try:
			data, addr = sock.recvfrom(4096)
			pc = pc + 1
			bytesin = bytesin + len(data)
			
		except socket.timeout as e:
			continue
			
		wt = time.time() - st
		
		wta = wta + wt
		wtc = wtc + 1
		
		if time.time() - wtlr > 5:
			print('longest-wait:%s' % hdt)
			hdt = 0
		
			pcd = time.time() - pcst
			pcst = time.time()
			print('packet-count/second:%s' % (pc / pcd))
			pc = 0
			
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
				print('sizes', len(keypub[0]), len(keypub[1]))
				data = struct.pack('>BII', PktCodeServer.PublicKey, nid, len(keypub[0])) + keypub[0] + keypub[1]
				print('send public key; expsz:%s keysz:%s' % (len(keypub[0]), len(keypub[1])))
				sock.sendto(data, addr)
				continue
			
			# they wish to setup the encryption between us
			if type == PktCodeClient.SetupEncryption:
				# the data has been encrypted using the public key
				data = data[1:]
				nid = struct.unpack('>I', data[0:4])[0]
				data = data[4:]
				# decrypt it and reveal the encryption key
				data = pubcrypt.decrypt(data, keypri)
				# create a unique link
				if addr not in links:
					links[addr] = {}
				# if too many connections from the same IP then
				# just ignore another one; i should make it send
				# a message to alert the client that this has
				# happened
				if len(links[addr]) > sconfig['max-links-from-addr']:
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
					print('\'', end='')
					#raise AddrNotInLinkException()
					continue
				if uid not in links[addr]:
					# let them know
					data = struct.pack('>B', PktCodeServer.NoLink)
					sock.sendto(data, addr)
					#raise InvalidLinkIDException()
					print('~', end='')
					continue
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
				if link['vman'].IsVectorGood(vector, sconfig['max-vector-ranges']) is False:
					# this means the vector could not be added to
					# the existing ranges AND it could not be added
					# as a single because we have hit our max range
					# limit
					print('.', end='')
					continue
				
				# they wish to connect to a block
				if type == PktCodeClient.BlockConnect:
					# they wish to connect with a block which will
					# give them access to the block if the supplied
					# credentials are correct
					#
					# TODO: add somekind of timeout here to prevent brute forcing
					#
					nid = struct.unpack_from('>I', data)[0]
					data = data[4:]
					bid = data
					if bid not in blocks:
						bid = bid.decode('utf8', 'ignore')
						
						# take care of a few things to prevent someone
						# from building their own arbitrary path
						bid = bid.replace('~', 'a')
						bid = bid.replace('/', 'b')
						bid = bid.replace('\\', 'c')
						l = len(bid) + 1
						while len(bid) != l:
							l = len(bid)
							bid = bid.replace('..', '.')
							
						
						# see if we load the block into memory from disk
						bpath = 'block.%s' % bid
					
						# this creates a block on demand with a default
						# number of bytes
						if sconfig['create-block-free'] is True:
							if os.path.exists(bpath) is False:
								# create it! (for demoing the service)
								block = {
										'fd':		None,
										'path':		'<replaceme>',
										'size':		sconfig['free-block-size'],
										'ref':		0,
										'maxref':	sconfig['block-max-ref'],
										'lmt':		0,
										'locks':	{},
										'mm':		None					
								}
								fd = open(bpath, 'w')
								pprint.pprint(block, fd)
								fd.close()
						
						# if block already loaded and opened
						# then use that block instead of making
						# new one...
						if bid not in blocks:
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
								data = struct.pack('>BIQ', PktCodeServer.BlockConnectFailure, nid, vector)
								data, _vector = BuildEncryptedMessage(link, data)
								link['outgoing'][_tmp] = (_tmp, 0, data)
								continue
					# they connected, so open the block if it is not open already
					block = blocks[bid]
					block['id'] = bid
					
					if block['ref'] > block['maxref']:
						data, _tmp = BuildEncryptedMessage(link, struct.pack('>BIQ', PktCodeServer.BlockConnectFailure, nid, vector))
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue				
					
					link['block'] = blocks[bid]
					block['ref'] = block['ref'] + 1
					
					if block['mm'] is None:
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
						block['fd'] = ofd
						block['mm'] = mmap.mmap(ofd, block['size'])
					print('send block connect success')
					data, _tmp = BuildEncryptedMessage(link, struct.pack('>BIQ', PktCodeServer.BlockConnectSuccess, nid, vector))
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
				
				mm = block['mm']					
				
				if type == PktCodeClient.WriteHold:
					offset, id = struct.unpack_from('>QI', data)
					data = data[8+4:]
					if offset + len(data) > block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						print('past end of buffer')
						continue
					
					# prevent DoS by limiting the number of write holds
					if len(link['wholds']) > 1000:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						print('too many holds')
						continue
					
					# we need to insert this write operation in the correct order
					# and using the vector should be the easiest;
					x = 0
					hx = None
					while x < len(link['wholds']):
						hold = link['wholds'][x]
						if hold[2] == id:
							if vector > hold[3]:
									# find the largest vector that
									# we are higher than and save
									# the list index for it
									hx = x
						x = x + 1
					if hx is None:
						# add to end of list
						#print('write hold inserted at end')
						link['wholds'].append((offset, data, id, vector))
					else:
						# insert after the highest found
						#print('write hold inserted at highest')
						link['wholds'].insert(hx + 1, (offset, data, id, vector))
					
					#link['wholds'].append((offset, data, id, vector))
					
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, offset, len(data))
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
			
				if type == PktCodeClient.FlushWriteHold:
					id = struct.unpack('>I', data)[0]
					# flush them if any
					_toremove = []
					for hold in link['wholds']:
						if hold[2] == id:
							_toremove.append(hold)
					for hold in _toremove:
						link['wholds'].remove(hold)
					_toremove = None
					
					print('flushed write hold for id:%x' % id)
					
					data = struct.pack('>BQ', PktCodeServer.FlushWriteHold, vector)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue						
			
				# lets the client verify all write are holding
				if type == PktCodeClient.GetWriteHoldCount:
					id = struct.unpack('>I', data)[0]
					cnt = 0
					for hold in link['wholds']:
						if hold[2] == id:
							cnt = cnt + 1
					data = struct.pack('>BQQ', PktCodeServer.GetWriteHoldCount, vector, cnt)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				
				# very critical section
				if type == PktCodeClient.DoWriteHold:
					id = struct.unpack('>I', data)[0]
					# all these writes need to happen, or else we fail
					# our contract with the client and risk their data
					# being in a corrupt state
					
					#print('doing write hold for id:%x all-count:%s' % (id, len(link['wholds'])))
					
					CriticalEnter()
					_toremove = []
					for hold in link['wholds']:
						if hold[2] == id:
							mm.seek(hold[0])
							mm.write(hold[1])
							_toremove.append(hold)
					# clear write holds matching the ID
					for hold in _toremove:
						link['wholds'].remove(hold)
					_toremove = None
					CriticalExit()
					
					#print('holds:%s' % link['wholds'])
					#print('		all-count:%s' % (len(link['wholds'])))
					
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, 0, 0)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
					
				if type == PktCodeClient.Copy:
					dst, src, length = struct.unpack_from('>QQQ', data)
					if dst + length > block['size'] or src + lenth > block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						continue			
					mm.move(dst, src, length)
					data = struct.pack('>BQQH', PktCodeServer.WriteSuccess, vector, 0, 0)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
					
				if type == PktCodeClient.Write:
					offset = struct.unpack_from('>Q', data)[0]
					data = data[8:]
					if offset + len(data) > block['size']:
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
					if offset + length > block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						print('read past end of block')
						continue
					#fd.seek(offset)
					mm.seek(offset)
					#_data = fd.read(length)
					_data = mm.read(length)
					data = struct.pack('>BQQH', PktCodeServer.ReadSuccess, vector, offset, length) + _data
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
					
				if type == PktCodeClient.BlockUnlock:
					offset = struct.unpack_from('>Q', data)[0]
					
					mm.seek(offset)
					cval = struct.unpack('>I', mm.read(4))[0]
					cref = struct.unpack('>I', mm.read(4))[0]
					_lid = struct.unpack('>I', lid)[0]
					
					# check if we own it (if not just dont unlock it)
					if cval == _lid:
						# decrement ref (if above zero)
						if cref > 0:
							cref = cref - 1
							mm.seek(offset + 4)
							mm.write(struct.pack('>I', cref))
						
						# unlock it
						if cref == 0:
							mm.seek(offset)
							mm.write(struct.pack('>I', 0))
							print('locks', link['locks'])
							link['locks'].remove(offset)
					
					data = struct.pack('>BQQ', PktCodeServer.BlockUnlockSuccess, vector, offset)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
					
				if type == PktCodeClient.BlockLock:
					offset, value = struct.unpack_from('>QI', data)
					if offset >= block['size']:
						data = struct.pack('>BQ', PktCodeServer.OperationFailure, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						print('lock beyond size')
						continue
						
					mm.seek(offset)
					cval = struct.unpack('>I', mm.read(4))[0]
					cref = struct.unpack('>I', mm.read(4))[0]
					_lid = struct.unpack('>I', lid)[0]
					
					print('cval:%x cref:%x lid:%x\n' % (cval, cref, _lid))
					
					# check if we own the lock, or if nobody owns it
					if cval == _lid or cval == 0:
						mm.seek(offset)
						mm.write(lid)
						mm.write(struct.pack('>I', cref + 1))
						# reply success
						data = struct.pack('>BQ', PktCodeServer.BlockLockSuccess, vector)
						data, _tmp = BuildEncryptedMessage(link, data)
						link['outgoing'][_tmp] = (_tmp, 0, data)
						
						if cval == 0:
							if offset not in link['locks']:
								link['locks'].append(offset)
						continue
					
					print('someone else holds lock')
					# somebody else owned the lock
					data = struct.pack('>BQ', PktCodeServer.BlockLockFailed, vector)
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
					oldval = mm.read(1)
					mm.seek(offset)
					mm.write(newvalue)
					data = struct.pack('>BQQB', PktCodeClient.Exchange8Success, vector, offset, oldval)
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
				if type == PktCodeClient.BlockSize:
					data = struct.pack('>BQQ', PktCodeServer.BlockSizeReply, vector, block['size'])
					data, _tmp = BuildEncryptedMessage(link, data)
					link['outgoing'][_tmp] = (_tmp, 0, data)
					continue
			print('[', end='')
			continue
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