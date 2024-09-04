using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtTokenBasedApi
{
    public class JWTManagerRepository : IJWTManagerRepository
    {
        Dictionary<string, string> userRecords = new Dictionary<string, string>
        {
            {"user1","password1" },
            {"user2","password2" },
            {"user3","password3" },
            {"user4","password4" },
        };

        private readonly IConfiguration _configuration;
        JWTManagerRepository(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        Tokens IJWTManagerRepository.Authenticate(Users user)
        {
            if(!userRecords.Any(x=>x.Key == user.UserName && x.Value == user.Password))
            {
                return null;
            }
            //if valid user
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var issuer = _configuration["Jwt:Issuer"];
            var audience = _configuration["Jwt:Audience"];
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti,
                Guid.NewGuid().ToString())
             }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = issuer,
                Audience = audience,
                SigningCredentials = new SigningCredentials
            (new SymmetricSecurityKey(tokenKey),
            SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return new Tokens
            {
                Token = tokenHandler.WriteToken(token)
            };
        }
    }
}
