import random
import math

def __gen_prime(N=10**8, bases=range(2,20000)):
    # XXX replace with a more sophisticated algorithm
    p = 1
    while any(pow(base, p-1, p) != 1 for base in bases):
        p = random.SystemRandom().randrange(N)
    return p

def __multinv(modulus, value):
    '''Multiplicative inverse in a given modulus

        >>> multinv(191, 138)
        18
        >>> 18 * 138 % 191
        1

    '''
    # http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    return result + modulus if result < 0 else result

def keygen(N):
    '''Generate public and private keys from primes up to N.

        >>> pubkey, privkey = keygen(2**64)
        >>> msg = 123456789012345
        >>> coded = pow(msg, 65537, pubkey)
        >>> plain = pow(coded, privkey, pubkey)
        >>> assert msg == plain

    '''
    # http://en.wikipedia.org/wiki/RSA
    prime1 = __gen_prime(N)
    prime2 = __gen_prime(N)
    totient = (prime1 - 1) * (prime2 - 1)
    return prime1 * prime2, __multinv(totient, 65537)

'''
	This function expects bytes not str.
'''
def toi256(data):
	t = 0
	n = 1
	for b in data:
		b = b
		t = t + (b * n)
		n = n * 256
	return t

def fromi256(i):
	o = []
	m = 1
	while m < i:
		m = m * 256
	if m > i:
		m = divmod(m, 256)[0]
	while i > 0:
		r = divmod(i, m)[0]
		o.insert(0, r)
		i = i - (r * m)
		m = m >> 8
	return bytes(o)
	
def crypt(data, pubkey):
	data =toi256(data)
	data = pow(data, 65537, pubkey)
	return fromi256(data)
	
def decrypt(data, prikey, pubkey):
	data = toi256(data)
	data = pow(data, prikey, pubkey)
	return fromi256(data)
	
'''
msg = 'hello'

pubkey, prikey = keygen(2**64)
print('pubkey:%s' % pubkey)
print('prikey:%s' % prikey)

coded = crypt(msg, pubkey)
plain = decrypt(coded, prikey, pubkey)
print(msg)
print(plain)
assert(msg == plain)
exit()
'''