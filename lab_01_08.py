# from pwn import remote, context
import pwn
from time import sleep

connection = pwn.remote("spyridon.ifi.uzh.ch", 26050)

connection.recvuntil(b"Enter your username: ", timeout=60)

# send our username followed by a newline (like `echo user | nc ...`)

connection.sendline(b"dhug")

connection.recvuntil(b"Select a question to solve (1-8) or 9 to exit:\n", timeout=60)

connection.sendline("8") 

buf = connection.recvrepeat(timeout=1)

print(buf)

sleep(1) 

connection.sendline("aa") 

buf = connection.recvrepeat()

print(f"\n {buf} \n")






