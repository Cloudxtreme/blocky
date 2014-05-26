{
	'link-idle-drop':			60,	# maximum time in seconds
									# a client can idle before
									# being dropped
	'public-key-bits':			64,	# the number of bits in the
									# generated public and private
									# keys
	'link-idle-check':		60 * 5,	# the time to wait before checking
									# for idle links
	'block-update-check':	60 * 5,	# the time to wait before checking
									# for updated block meta-data files
	'resend-delay':			5,		# the number of seconds to wait
									# before resending a packet
	'max-links-from-addr':	25,		# maximum links from single address (DoS prevention)
	'max-vector-ranges':	40,		# maximum vector ranges (DoS prevention) per link
	'create-block-free':	True,	# allow anyone to create a new block
	'free-block-size':		1024 * 1024 * 50,	# the default size of a free block
	'block-max-ref':		40,		# maximum links (clients) per block
									# this is used when creating a free block, because
									# the block meta-data file is expected to 
									# specify the max refs
	'max-links':			100,	# maximum links (clients) [NOT IMPLEMENTED]
}