using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using GoogleAndJwtToken.Middlewares;
using GoogleAndJwtToken.Settings;
using System.Text;
using GoogleAndJwtToken.Models;
using GoogleAndJwtToken.Service;
using FluentValidation;
using GoogleAndJwtToken.Validation;
using GoogleAndJwtToken.Dtos;
using GoogleAndJwtToken.Helpers;
using GoogleAndJwtToken.Common.Payloads.Requests;
using AutoMapper;
using GoogleAndJwtToken.Mapper;

namespace GoogleAndJwtToken.Extensions;

public static class ServicesExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // Đăng ký middleware xử lý ngoại lệ
        services.AddScoped<ExceptionMiddleware>();
        services.AddControllers();
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();

        //Add Mapper
        var mapperConfig = new MapperConfiguration(mc =>
        {
            mc.AddProfile(new ApplicationMapper());
        });

        IMapper mapper = mapperConfig.CreateMapper();
        services.AddSingleton(mapper);

        // Lấy cấu hình JwtSettings từ file cấu hình và thiết lập
        var jwtSettings = configuration.GetSection(nameof(JwtSettings)).Get<JwtSettings>();
        services.Configure<JwtSettings>(val =>
        {
            val.Key = jwtSettings.Key;
        });

        services.AddAuthorization();

        // Cấu hình xác thực JWT
        services.AddAuthentication(options =>
            {
                // Thiết lập mặc định scheme để sử dụng JWT Bearer
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    // Khóa bí mật để ký token
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key)),
                    ValidateIssuer = false, // Tắt xác thực Issuer
                    ValidateAudience = false, // Tắt xác thực Audience
                    ValidateLifetime = true, // Bật xác thực thời hạn của token
                    ValidateIssuerSigningKey = true // Bật xác thực khóa ký của token
                };
            });
        

        

        //Add connection to database
        services.AddDbContext<GoogleAndJwtTokenContext>(opt =>
        {
            opt.UseSqlServer(configuration.GetConnectionString("DbConnection"));
        });

        //Add Services
        services.AddScoped<IdentityService>();


        //Add Validation
        services.AddScoped<IValidator<SignupRequest>, SignupValidation>();

        return services;
    }
}