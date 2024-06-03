using GoogleAndJwtToken.Extensions;
using GoogleAndJwtToken.Middlewares;
using Microsoft.OpenApi.Models;

namespace GoogleAndJwtToken
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            //Add services to the container.
            builder.Services.AddInfrastructure(builder.Configuration);
            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();


            builder.Services.AddSwaggerGen(option =>
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
            builder.Services.AddCors(option =>
                option.AddPolicy("CORS", builder =>
                    builder.AllowAnyMethod().AllowAnyHeader().AllowCredentials().SetIsOriginAllowed((host) => true)));


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }
            app.UseCors("CORS");

            app.UseHttpsRedirection();

            app.UseMiddleware<ExceptionMiddleware>();

            app.UseAuthentication();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
