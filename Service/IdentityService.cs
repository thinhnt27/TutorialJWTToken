using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using GoogleAndJwtToken.Common.Payloads.Requests;
using GoogleAndJwtToken.Dtos.Auth;
using GoogleAndJwtToken.Exceptions;
using GoogleAndJwtToken.Helpers;
using GoogleAndJwtToken.Settings;
using GoogleAndJwtToken.Models;
using Microsoft.EntityFrameworkCore;
using GoogleAndJwtToken.Dtos;
using AutoMapper;

namespace GoogleAndJwtToken.Service;

public class IdentityService
{
    private readonly JwtSettings _jwtSettings;
    private readonly GoogleAndJwtTokenContext _context;
    private readonly IMapper _mapper;

    public IdentityService(IOptions<JwtSettings> jwtSettingsOptions, GoogleAndJwtTokenContext context, IMapper mapper)
    {
        _jwtSettings = jwtSettingsOptions.Value;
        _context = context;
        _mapper = mapper;

    }



    //Signup for User
    public async Task<LoginResult> Signup(SignupRequest req)
    {
        var user = _context.Users.Where(c => c.UserName == req.UserName).FirstOrDefault();
        if (user is not null)
        {
            throw new BadRequestException("username or email already exists");
        }

        var createUser = await _context.AddAsync(new User
        {
            UserName = req.UserName,
            Password = SecurityUtil.Hash(req.Password),
            //Password = SecurityUtil.Hash("supersuperpasshashed"),
            Email = req.Email,
            Phone = req.Phone,
            Address = req.Address,
            RoleId = req.RoleId,
            RegistrationDate = DateOnly.FromDateTime(DateTime.Now),
        });
        
        var res = await _context.SaveChangesAsync();
        if(res > 0)
        {
            return new LoginResult
            {
                Authenticated = true,
                Token = CreateJwtToken(createUser.Entity)
            };
        }
        else
        {
            return new LoginResult
            {
                Authenticated = false,
                Token = null
            };
        }
    }


    //Login for User
    public LoginResult Login(string username, string password)
    {
        var user = _context.Users.Where(c => c.UserName == username).FirstOrDefault();


        if (user is null)
        {
            return new LoginResult
            {
                Authenticated = false,
                Token = null,
            };
        }
        var userRole = _context.Roles.Where(ur => ur.RoleId == user.RoleId).FirstOrDefault();

        user.Role = userRole!;

        var hash = SecurityUtil.Hash(password);
        if (!user.Password.Equals(hash))
        {
            return new LoginResult
            {
                Authenticated = false,
                Token = null,
            };
        }

        return new LoginResult
        {
            Authenticated = true,
            Token = CreateJwtToken(user),
        };
    }

    //Generate JWT Token for User
    private SecurityToken CreateJwtToken(User user)
    {
        // Lấy thời gian hiện tại theo giờ quốc tế (UTC)
        var utcNow = DateTime.UtcNow;

        // Lấy thông tin vai trò của người dùng từ cơ sở dữ liệu
        var userRole = _context.Roles.Where(u => u.RoleId == user.RoleId).FirstOrDefault();

        // Nếu vai trò không tồn tại, ném ra ngoại lệ
        if (userRole is null) throw new BadRequestException("Role not found");

        // Tạo danh sách các claims chứa thông tin người dùng
        var authClaims = new List<Claim>
        {
            // Claim chứa UserId của người dùng
            new(JwtRegisteredClaimNames.NameId, user.UserId.ToString()),
/*            new(JwtRegisteredClaimNames.Sub, user.UserName),*/

            // Claim chứa email của người dùng
            new(JwtRegisteredClaimNames.Email, user.Email),

            // Claim chứa vai trò của người dùng
            new(ClaimTypes.Role, userRole.RoleName),

            // Claim chứa một ID duy nhất cho token (JWT ID)
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        // Chuyển khóa bí mật từ dạng chuỗi sang mảng byte
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            //// Gán các claims cho token
            Subject = new ClaimsIdentity(authClaims),
            // Thiết lập thuật toán và khóa ký token
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
            // Thiết lập thời gian hết hạn cho token (1 giờ kể từ thời điểm hiện tại)
            Expires = utcNow.Add(TimeSpan.FromHours(1)),
        };
        // Tạo một handler để xử lý token
        var handler = new JwtSecurityTokenHandler();
        // Tạo token dựa trên các mô tả đã thiết lập
        var token = handler.CreateToken(tokenDescriptor);

        return token;
    }

    //Get all Users and map UserModel
    public List<UserModel> GetAllUsers()
    {
        var users = _context.Users.ToList();
        return _mapper.Map<List<UserModel>>(users);
    }

    
}