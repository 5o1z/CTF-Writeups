# Packer

## Description

> Reverse this linux executable?

## Solution

Nhìn vào size của file ta có thể thấy file này đã được packed

{% hint style="info" %}
**Packer** là một công cụ hoặc chương trình được sử dụng để nén hoặc mã hóa các file (thường là file thực thi) nhằm mục đích bảo vệ hoặc giảm kích thước file trước khi phân phối. Các packer làm thay đổi cấu trúc của file, nhưng vẫn giữ được chức năng của chương trình khi chạy.
{% endhint %}

Hãy nhìn xem file này có những gì

```bash
➜  rev file out
out: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
➜  rev strings -n 8 out
<...>
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.95 Copyright (C) 1996-2018 the UPX Team. All Rights Reserved. $
/proc/self/exe
GCC: (Ubuntu 9.4.0-1u
<...>
```

Ta có thể thấy file này dùng UPX để pack, vì vậy để ta có thể phân tích được nhưng gì có trong file thì ta phải unpack

```bash
➜  rev upx -d out -o unpacked
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    877724 <-    336520   38.34%   linux/amd64   unpacked

Unpacked 1 file.
```

Và khi ta chạy file đó nó sẽ hỏi ta nhập password để được mở file

```bash
➜  rev ./unpacked
Enter the password to unlock this file: abcd
You entered: abcd

Access denied
```

Hãy dùng lại **strings** xem nó có gì sau khi ta unpack

```bash
➜  rev strings unpacked -n 8
<...>
Enter the password to unlock this file:
You entered: %s
Password correct, please see flag: 7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f39343130343638327d
Access denied
xeon_phi
<...>
```

Output strings cho ta hex của flag, hãy decode nó:

```bash
➜  rev echo '7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f39343130343638327d' | xxd -r -p
picoCTF{U9X_UnP4ck1N6_B1n4Ri3S_94104682}
```
