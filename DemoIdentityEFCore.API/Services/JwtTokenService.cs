using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoIdentityEFCore.API.Services
{
    public interface IJwtTokenService
    {
        SecurityToken CreateSecurityToken(ClaimsIdentity identity);
        string WriteToken(SecurityToken token);
    }
    public class JwtTokenService : IJwtTokenService
    {
        private readonly IConfiguration _configuration;

        public JwtTokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        private static JwtSecurityTokenHandler TokenHandler => new JwtSecurityTokenHandler();

        public SecurityToken CreateSecurityToken(ClaimsIdentity identity)
        {
            var tokenDescriptor = GetTokenDescriptor(identity);

            return TokenHandler.CreateToken(tokenDescriptor);
        }

        public string WriteToken(SecurityToken token)
        {
            return TokenHandler.WriteToken(token);
        }

        private SecurityTokenDescriptor GetTokenDescriptor(ClaimsIdentity identity)
        {

            string Audience = _configuration["JwtSettings:Audience"] ?? throw new ArgumentNullException(nameof(Audience));
            string Issuer = _configuration["JwtSettings:Issuer"] ?? throw new ArgumentNullException(nameof(Audience));
            string SigningKey = _configuration["JwtSettings:SigningKey"] ?? throw new ArgumentNullException(nameof(SigningKey));

            var secretKey = Encoding.ASCII.GetBytes(SigningKey);

            return new SecurityTokenDescriptor()
            {
                Subject = identity,
                Expires = DateTime.Now.AddHours(1),
                Audience = Audience,
                Issuer = Issuer,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature)
            };
        }
    }
}
