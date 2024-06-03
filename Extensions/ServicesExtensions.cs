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

namespace GoogleAndJwtToken.Extensions;

public static class ServicesExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<ExceptionMiddleware>();
        services.AddControllers();
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();


        ////Set time for PostgreSQL
        //AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

        var jwtSettings = configuration.GetSection(nameof(JwtSettings)).Get<JwtSettings>();
        services.Configure<JwtSettings>(val =>
        {
            val.Key = jwtSettings.Key;
        });

        services.AddAuthorization();

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true
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
        services.AddScoped<IValidator<UserModel>, UserValidation>();

        return services;
    }
}