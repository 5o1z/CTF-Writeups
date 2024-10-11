"""
28777 25455 17236 18043 12598 24418 26996 29535 26990 29556 13108 25695 28518 24376 24368 13411 12343 13872 25725

28777 là một giá trị 16-bit được biểu diễn dưới dạng nhị phân: 01110000 10101001
Example: 28777 = ord(flag[i]) << 8 = 285777 / 256 = 112 ---> ord(flag[1]) + (112  x 256) = 28777 
		 28777 = ord(flag[i]) << 8 ---> ord(flag[i]) = 28777 >> 8
		 
Ý tưởng ở đây là chúng ta muốn tách giá trị này thành 2 phần:
- Byte cao (8 bit đầu): lấy giá trị đầu tiên của flag (ord(flag[i]))
- Byte thấp (8 bit cuối): lấy giá trị thứ hai của flag (ord(flag[i+1]))

1. Dịch giá trị sang phải 8 bit để lấy byte cao nhất:
   28777 >> 8 = 01110000 (tương đương với 112 trong hệ thập phân)
   Giá trị 112 này chính là ord(flag[0]) trong biểu thức.
2. Để lấy giá trị tiếp theo (byte thấp nhất):
   Ta thực hiện phép AND với 0xFF (tức là 255) để giữ lại 8 bit cuối của giá trị ban đầu:
   28777 & 0xFF = 10101001 (tương đương với 105 trong hệ thập phân)
   Giá trị 105 này chính là ord(flag[1]) trong biểu thức.
"""

def decode_array(arr):
    flag = ""
    
    for value in arr:
        # Dịch chuyển 8 bit sang phải để lấy byte cao nhất (8 bit đầu tiên)
        # & 0xFF để đảm bảo chỉ giữ lại đúng 8 bit và loại bỏ các bit không mong muốn
        char1 = (value >> 8) & 0xFF
        
        # Lấy byte thấp nhất (8 bit cuối) bằng cách AND với 0xFF
        # Điều này giúp tách riêng phần này khỏi giá trị ban đầu
        char2 = value & 0xFF
        
        # Chuyển đổi các giá trị ASCII thành ký tự và ghép vào chuỗi flag
        # chr(char1) và chr(char2) chuyển giá trị thành ký tự tương ứng
        flag += chr(char1) + chr(char2)
    
    return flag

# Mảng đã cho chứa các giá trị 16-bit
array = [28777, 25455, 17236, 18043, 12598, 24418, 26996, 29535, 26990, 29556, 
         13108, 25695, 28518, 24376, 24368, 13411, 12343, 13872, 25725]

# Giải mã mảng và in ra chuỗi flag
decoded_flag = decode_array(array)
print(f"The decoded flag is: '{decoded_flag}'")


