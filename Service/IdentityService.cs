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
        var user = _context.Users.Where(c => c.UserName == req.UserName || c.Email == req.Email).FirstOrDefault();
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
                Token = CreateJwtToken(createUser.Entity),
                RefreshToken = CreateJwtRefreshToken(createUser.Entity)
            };
        }
        else
        {
            return new LoginResult
            {
                Authenticated = false,
                Token = null,
                RefreshToken = null
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
                RefreshToken = null
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
                RefreshToken = null
            };
        }

        return new LoginResult
        {
            Authenticated = true,
            Token = CreateJwtToken(user),
            RefreshToken = CreateJwtRefreshToken(user)
        };
    }

    //Generate JWT Token for User
    private SecurityToken CreateJwtToken(User user)
    {
        var utcNow = DateTime.UtcNow;

        var userRole = _context.Roles.Where(u => u.RoleId == user.RoleId).FirstOrDefault();

        if (userRole is null) throw new BadRequestException("Role not found");

        // Tạo danh sách các claims chứa thông tin người dùng
        var authClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.NameId, user.UserId.ToString()),

            new(JwtRegisteredClaimNames.Email, user.Email),

            new(ClaimTypes.Role, userRole.RoleName),

            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        // Chuyển khóa bí mật từ dạng chuỗi sang mảng byte
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            // Gán các claims cho token Payload
            Subject = new ClaimsIdentity(authClaims),
            // Thiết lập thuật toán và khóa ký token Header
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
            // Thiết lập thời gian hết hạn cho token
            Expires = utcNow.Add(TimeSpan.FromHours(1)),
        };
        // Tạo một handler để xử lý token
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);

        return token;
    }

    //Generate JWT Token for User
    private SecurityToken CreateJwtRefreshToken(User user)
    {
        var utcNow = DateTime.UtcNow;

        var userRole = _context.Roles.Where(u => u.RoleId == user.RoleId).FirstOrDefault();

        if (userRole is null) throw new BadRequestException("Role not found");

        // Tạo danh sách các claims chứa thông tin người dùng
        var authClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.NameId, user.UserId.ToString()),

            new(JwtRegisteredClaimNames.Email, user.Email),

            new(ClaimTypes.Role, userRole.RoleName),

            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        // Chuyển khóa bí mật từ dạng chuỗi sang mảng byte
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            // Gán các claims cho token Payload
            Subject = new ClaimsIdentity(authClaims),
            // Thiết lập thuật toán và khóa ký token Header
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
            // Thiết lập thời gian hết hạn cho token
            Expires = utcNow.Add(TimeSpan.FromHours(240)),
        };
        // Tạo một handler để xử lý token
        var handler = new JwtSecurityTokenHandler();
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