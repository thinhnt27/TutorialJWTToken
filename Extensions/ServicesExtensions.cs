using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using GoogleAndJwtToken.Settings;
using System.Text;
using GoogleAndJwtToken.Models;
using GoogleAndJwtToken.Service;
using AutoMapper;
using GoogleAndJwtToken.Mapper;
using Microsoft.OpenApi.Models;

namespace GoogleAndJwtToken.Extensions;

public static class ServicesExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
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
        services.AddControllers();
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(option =>
        {
            // Cấu hình tài liệu Swagger với thông tin về API
            option.SwaggerDoc("v1", new OpenApiInfo { Title = "API", Version = "v1" });

            // Thêm định nghĩa bảo mật cho Swagger sử dụng JWT Bearer
            option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                In = ParameterLocation.Header, // Định nghĩa vị trí của thông tin bảo mật trong header
                Description = "Please enter a valid token", // Mô tả cho người dùng về việc nhập token
                Name = "Authorization", // Tên của header
                Type = SecuritySchemeType.Http, // Loại scheme là HTTP
                BearerFormat = "JWT", // Định dạng của token là JWT
                Scheme = "Bearer" // Scheme là Bearer
            });
            // Thiết lập yêu cầu bảo mật cho các endpoint trong Swagger
            option.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type=ReferenceType.SecurityScheme, // Loại tham chiếu là SecurityScheme
                                Id="Bearer" // Id của SecurityScheme là Bearer
                            }
                        },
                        new string[] {} // Không có yêu cầu scope cụ thể
                    }
                });
        });
        services.AddCors(option =>
            option.AddPolicy("CORS", builder =>
                builder.AllowAnyMethod().AllowAnyHeader().AllowCredentials().SetIsOriginAllowed((host) => true)));
        //Add Services
        services.AddScoped<IdentityService>();


        return services;
    }
}