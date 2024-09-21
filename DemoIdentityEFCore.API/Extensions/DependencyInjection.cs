using DemoIdentityEFCore.API.Data;
using DemoIdentityEFCore.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace DemoIdentityEFCore.API.Extensions
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddDatabaseConfiguration(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApplicationIdentityDbContext>(options =>
                options.UseInMemoryDatabase("InMemoDb"));
                //options.UseSqlServer(configuration.GetConnectionString("Default")));
            return services;
        }

        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            })
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtSettings:SigningKey"] ?? throw new InvalidOperationException())),
                        ValidateIssuer = true,
                        ValidIssuer = configuration["JwtSettings:Issuer"],
                        ValidateAudience = true,
                        ValidAudience = configuration["JwtSettings:Audience"],
                        RequireExpirationTime = false,
                        ValidateLifetime = true,
                    };
                    // Optional: Log errors for debugging
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            // Log the exception for debugging
                            Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                            return Task.CompletedTask;
                        }
                    };
                });
            return services;
        }

        public static IServiceCollection AddIdentityConfiguration(this IServiceCollection services)
        {
            //AddDefaultIdentity is from Microsoft.AspNetCore.Identity.UI
            services.AddDefaultIdentity<IdentityUser>(options =>
            {
                options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultProvider;
                //options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultEmailProvider;

            })
                .AddEntityFrameworkStores<ApplicationIdentityDbContext>();
            return services;
        }

        public static IServiceCollection ConfigureServices(this IServiceCollection services)
        {
            services.AddScoped<IEmailService, EmailService>();
            services.AddScoped<IJwtTokenService, JwtTokenService>();

            return services;
        }
    }
}
