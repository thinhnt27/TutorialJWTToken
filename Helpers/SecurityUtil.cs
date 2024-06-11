using System.Security.Cryptography;
using System.Text;

namespace GoogleAndJwtToken.Helpers;

public static class SecurityUtil
{
    public static string Hash(string input)
    {
        // Tạo một đối tượng SHA256 mới để tính toán hash
        using var sha256 = SHA256.Create();

        // Chuyển đổi chuỗi đầu vào thành mảng byte sử dụng mã hóa UTF-8
        var bytes = Encoding.UTF8.GetBytes(input);

        // Tính toán hash cho mảng byte đầu vào
        var hash = sha256.ComputeHash(bytes);

        // Tạo một StringBuilder để xây dựng chuỗi kết quả từ các byte của hash
        var stringBuilder = new StringBuilder();


        // Duyệt qua từng byte trong hash
        foreach (var b in hash)
        {
            // Chuyển đổi mỗi byte thành chuỗi hệ thập lục phân (hex) và thêm vào StringBuilder
            stringBuilder.Append(b.ToString("x2"));
        }
            
        return stringBuilder.ToString();
    }

}