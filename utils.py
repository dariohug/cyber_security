import pwn
from time import sleep

def login(challenge):
    connection = pwn.remote("spyridon.ifi.uzh.ch", 26050)

    connection.recvuntil(b"Enter your username: ", timeout=60)

    # send our username followed by a newline (like `echo user | nc ...`)

    connection.sendline(b"dhug")

    connection.recvuntil(b"Select a question to solve (1-8) or 9 to exit:\n", timeout=60)

    connection.sendline(str(challenge)) 

    buf = connection.recvrepeat(timeout=1)

    print(f"\n{buf.decode(errors='replace')}\n")

    sleep(1)
    return connection, buf

def print_buf(con): 
    buf = con.recvrepeat(timeout=1)
    print(f"\n{buf.decode(errors='replace')}\n")