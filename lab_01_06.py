import pwn
from time import sleep
from utils import login, print_buf


con, buf = login(6)

lines = buf.decode(errors="replace").split("\n")

for line in lines:
    if "p1:" in line.lower():
        plain_text_1 = line.split()[-1]
    if "c1:" in line.lower(): 
        cipher_text_1 = line.split()[-1]
    if "c2:" in line.lower(): 
        cipher_text_2 = line.split()[-1]

print(f"Plain Text 1: {plain_text_1}")
print(f"Cipher Text 1: {cipher_text_1}")
print(f"Cipher Text 2: {cipher_text_2}")

