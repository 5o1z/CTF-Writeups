# Secure Bank

## Description

> Can you crack the bank?

## Solution

<figure><img src="../../../../.gitbook/assets/image (189).png" alt=""><figcaption></figcaption></figure>

{% tabs %}
{% tab title="main" %}
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v4; // [rsp+4h] [rbp-Ch] BYREF
  int v5; // [rsp+8h] [rbp-8h] BYREF
  unsigned int _2fa_code; // [rsp+Ch] [rbp-4h]

  banner(argc, argv, envp);
  login_message();
  printf("Enter superadmin PIN: ");
  __isoc99_scanf("%u", &v5);
  if ( v5 == 1337 )
  {
    _2fa_code = generate_2fa_code(1337LL);
    printf("Enter your 2FA code: ");
    __isoc99_scanf("%u", &v4);
    validate_2fa_code(v4, _2fa_code);
    return 0;
  }
  else
  {
    puts("Access Denied! Incorrect PIN.");
    return 1;
  }
}
```
{% endtab %}

{% tab title="generate_2fa_code" %}
```c
__int64 __fastcall generate_2fa_code(int a1)
{
  int i; // [rsp+Ch] [rbp-Ch]
  int v3; // [rsp+10h] [rbp-8h]
  unsigned int v4; // [rsp+14h] [rbp-4h]

  v4 = 48879 * a1;
  v3 = 48879 * a1;
  for ( i = 0; i <= 9; ++i )
  {
    v4 = obscure_key(v4);
    v3 = ((v4 >> ((char)i % 5)) ^ (v4 << (i % 7))) + __ROL4__(v4 ^ v3, 5);
  }
  return v3 & 0xFFFFFF;
}
```
{% endtab %}

{% tab title="obscure_key" %}
```c
__int64 __fastcall obscure_key(int a1)
{
  return (4919 * __ROL4__(a1 ^ 0xA5A5A5A5, 3)) ^ 0x5A5A5A5Au;
}
```
{% endtab %}

{% tab title="validate_2fa_code" %}
```c
int __fastcall validate_2fa_code(int a1, int a2)
{
  if ( a1 != a2 )
    return puts("Access Denied! Incorrect 2FA code.");
  puts("Access Granted! Welcome, Superadmin!");
  return printf("Here is your flag: %s\n", "INTIGRITI{fake_flag}");
}
```
{% endtab %}
{% endtabs %}

Như ta thấy chương trình yêu cầu ta nhập mã PIN, và nếu ta nhập mã PIN là **1337** thì nó sẽ bắt ta nhập 2FA code. Vấn đề được đặt ra ở đây là 2FA code là gì? Và nếu có được 2FA code thì ta sẽ có được flag

### Cách 1

Khi nhìn disassembly của hàm **main()** ta có thể thấy khi nó gọi hàm **generate\_2fa\_code()** thì nó di chuyển giá trị của **eax** vào **var\_4 (\_2fa\_code)**&#x20;

<figure><img src="../../../../.gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

Và để biết được giá trị nó di chuyển là bao nhiêu thì ta hãy debug nó bằng GDB:

```bash
gef➤  b *main+117
Breakpoint 1 at 0x1386
gef➤  r
Starting program: /home/alter/CTFs/1337UP/Reverse/secure_bank/secure_bank
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
****************************************
*         Welcome to SecureBank        *
*    Your trusted partner in security  *
****************************************

========================================
=   SecureBank Superadmin Login System =
========================================

Enter superadmin PIN: 1337

Breakpoint 1, 0x0000555555555386 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x568720
$rbx   : 0x00007fffffffdc18  →  0x00007fffffffde96  →  "/home/alter/CTFs/1337UP/Reverse/secure_bank/secure[...]"
$rcx   : 0x2
$rdx   : 0x57c77bc8
$rsp   : 0x00007fffffffdae0  →  0x00007fffffffdbd0  →  0x0000555555555070  →  <_start+0000> xor ebp, ebp
$rbp   : 0x00007fffffffdaf0  →  0x00007fffffffdb90  →  0x00007fffffffdbf0  →  0x0000000000000000
$rsi   : 0xd5f1def
$rdi   : 0xa8497d36
$rip   : 0x0000555555555386  →  <main+0075> mov DWORD PTR [rbp-0x4], eax
$r8    : 0xa
$r9    : 0x0
$r10   : 0x00007ffff7f56fc0  →  0x0000000100000000
$r11   : 0x00007ffff7fa88e0  →  0x00000000fbad2288
$r12   : 0x1
$r13   : 0x0
$r14   : 0x0000555555557dd8  →  0x0000555555555110  →  <__do_global_dtors_aux+0000> endbr64
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdae0│+0x0000: 0x00007fffffffdbd0  →  0x0000555555555070  →  <_start+0000> xor ebp, ebp     ← $rsp
0x00007fffffffdae8│+0x0008: 0x00007fff00000539
0x00007fffffffdaf0│+0x0010: 0x00007fffffffdb90  →  0x00007fffffffdbf0  →  0x0000000000000000     ← $rbp
0x00007fffffffdaf8│+0x0018: 0x00007ffff7dcf1ca  →  <__libc_start_call_main+007a> mov edi, eax
0x00007fffffffdb00│+0x0020: 0x00007fffffffdb40  →  0x0000555555557dd8  →  0x0000555555555110  →  <__do_global_dtors_aux+0000> endbr64
0x00007fffffffdb08│+0x0028: 0x00007fffffffdc18  →  0x00007fffffffde96  →  "/home/alter/CTFs/1337UP/Reverse/secure_bank/secure[...]"
0x00007fffffffdb10│+0x0030: 0x0000000155554040
0x00007fffffffdb18│+0x0038: 0x0000555555555311  →  <main+0000> push rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555537c <main+006b>      mov    eax, DWORD PTR [rbp-0x8]
   0x55555555537f <main+006e>      mov    edi, eax
   0x555555555381 <main+0070>      call   0x5555555551fa <generate_2fa_code>
●→ 0x555555555386 <main+0075>      mov    DWORD PTR [rbp-0x4], eax
   0x555555555389 <main+0078>      lea    rax, [rip+0xe7b]        # 0x55555555620b
   0x555555555390 <main+007f>      mov    rdi, rax
   0x555555555393 <main+0082>      mov    eax, 0x0
   0x555555555398 <main+0087>      call   0x555555555040 <printf@plt>
   0x55555555539d <main+008c>      lea    rax, [rbp-0xc]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "secure_bank", stopped 0x555555555386 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555386 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0x7fffffffdb00:
 rip = 0x555555555386 in main; saved rip = 0x7ffff7dcf1ca
 Arglist at 0x7fffffffdaf0, args:
 Locals at 0x7fffffffdaf0, Previous frame's sp is 0x7fffffffdb00
 Saved registers:
  rbp at 0x7fffffffdaf0, rip at 0x7fffffffdaf8
gef➤  i r
rax            0x568720            0x568720
rbx            0x7fffffffdc18      0x7fffffffdc18
rcx            0x2                 0x2
rdx            0x57c77bc8          0x57c77bc8
rsi            0xd5f1def           0xd5f1def
rdi            0xa8497d36          0xa8497d36
rbp            0x7fffffffdaf0      0x7fffffffdaf0
rsp            0x7fffffffdae0      0x7fffffffdae0
r8             0xa                 0xa
r9             0x0                 0x0
r10            0x7ffff7f56fc0      0x7ffff7f56fc0
r11            0x7ffff7fa88e0      0x7ffff7fa88e0
r12            0x1                 0x1
r13            0x0                 0x0
r14            0x555555557dd8      0x555555557dd8
r15            0x7ffff7ffd000      0x7ffff7ffd000
rip            0x555555555386      0x555555555386 <main+117>
eflags         0x202               [ IF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0
fs_base        0x7ffff7da2740      0x7ffff7da2740
gs_base        0x0                 0x0
```

Chúng ta có thể thấy giá trị của eax khi di chuyển vào rbp-0x4 là 0x568720 tương đương 5670688

Và đó là 2FA code, hãy dùng nó nhập vào và lấy flag

```bash
➜  secure_bank nc securebank.ctf.intigriti.io 1335
****************************************
*         Welcome to SecureBank        *
*    Your trusted partner in security  *
****************************************

========================================
=   SecureBank Superadmin Login System =
========================================

Enter superadmin PIN: 1337
Enter your 2FA code: 5670688
Access Granted! Welcome, Superadmin!
Here is your flag: INTIGRITI{pfff7_wh47_2f4?!}
```

### Cách 2

Vì phần pseudo code chỉ đơn giản là việc generate 2FA code nên ta có thể rebuild nó lại bằng C và chạy nó để xem 2FA code là gì

```c
#include <stdio.h>

unsigned int obscure_key(int a1) {
return (4919 * __ROL4__(a1 ^ 0xA5A5A5A5, 3)) ^ 0x5A5A5A5A;
}

unsigned int generate_2fa_code(int a1) {
int i;
unsigned int v3, v4;

v4 = 48879 * a1;
v3 = 48879 * a1;
for (i = 0; i <= 9; ++i) {
v4 = obscure_key(v4);
v3 = ((v4 >> (i % 5)) ^ (v4 << (i % 7))) + __ROL4__(v4 ^ v3, 5);
v3 &= 0xFFFFFFFF;
}
return v3 & 0xFFFFFF;
}

int main() {
int a1 = 1337;
unsigned int code = generate_2fa_code(a1);
printf("Generated 2FA code: %u\n", code);
return 0;
}
```

```bash
➜  secure_bank gcc secure_bank.c -o solve
➜  secure_bank ./solve
Generated 2FA code: 5670688
```
