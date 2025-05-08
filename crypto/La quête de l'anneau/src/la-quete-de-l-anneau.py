#!/usr/bin/env python3

import json
import os
from Crypto.Util.number import *
from Crypto.Random.random import randrange
from math import gcd

class Cipher:

	def __init__(self, size = 512):
		self.s = 2**size + randrange(2**size)
		self.bs = size // 8

	def encrypt(self, m, data = False):
		assert len(m) % self.bs == 0, f"Error: wrong length ({len(m)})"
		C = []
		for i in range(0, len(m), self.bs):
			iv = randrange(self.s)
			while gcd(iv,self.s) != 1:
				iv = randrange(self.s)
			b = int.from_bytes(m[i:i + self.bs],"big")
			if not data:
				C.append({
					"iv" : iv,
					"c" : (b * iv) % self.s,
				})
			else:
				C.append({
					"m" : b,
					"iv" : iv,
					"c" : (b * iv) % self.s,
				})

		return C

	def decrypt(self, c):
		r = b""
		for d in c:
			m = d["c"] * pow(d["iv"], -1, self.s) % self.s
			r += int.to_bytes(m, self.bs,"big")
		return r

if __name__ == "__main__":

	flag = open("flag.txt", "rb").read().strip()
	assert len(flag) == 64, "Error: wrong flag length."

	E = Cipher()

	m = os.urandom(64).hex()
	data = E.encrypt(m.encode(), data = True)

	C = E.encrypt(flag)
	assert flag == E.decrypt(C), "Error: decryption test failed."

	print(json.dumps({
		"data" : data,
		"C" : C
	}, indent = 4))
