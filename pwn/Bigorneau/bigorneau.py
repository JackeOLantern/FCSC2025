import os
import sys
import tempfile
import subprocess

try:
	print("Enter your shellcode (hex, at most 128 bytes):")
	SC = bytes.fromhex(input())

	# Check shellcode constraints
	assert len(SC) <= 128
	assert len(set(SC)) <= 6

	# Empty registers
	SC = b"\x48\x31\xed" + SC # xor rbp, rbp
	SC = b"\x4d\x31\xff" + SC # xor r15, r15
	SC = b"\x4d\x31\xf6" + SC # xor r14, r14
	SC = b"\x4d\x31\xed" + SC # xor r13, r13
	SC = b"\x4d\x31\xe4" + SC # xor r12, r12
	SC = b"\x4d\x31\xdb" + SC # xor r11, r11
	SC = b"\x4d\x31\xd2" + SC # xor r10, r10
	SC = b"\x4d\x31\xc9" + SC # xor  r9,  r9
	SC = b"\x4d\x31\xc0" + SC # xor  r8,  r8
	SC = b"\x48\x31\xf6" + SC # xor rsi, rsi
	SC = b"\x48\x31\xff" + SC # xor rdi, rdi
	SC = b"\x48\x31\xd2" + SC # xor rdx, rdx
	SC = b"\x48\x31\xc9" + SC # xor rcx, rcx
	SC = b"\x48\x31\xdb" + SC # xor rbx, rbx
	SC = b"\x48\x31\xc0" + SC # xor rax, rax

	# Prepare running the shellcode
	tmp = tempfile.mkdtemp(dir = "/dev/shm/", prefix = bytes.hex(os.urandom(8)))
	fn = os.path.join(tmp, "shellcode")
	with open(fn, "wb") as f:
	    f.write(SC)

	# Running the shellcode
	subprocess.run(["./bigorneau", fn], stderr = sys.stdout, timeout = 120)

	# Cleaning
	os.remove(fn)
	os.rmdir(tmp)

except:
	print("Please check your inputs.")
