using JWTAuthenication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthenication.Services
{
    public class JwtTokenService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly ILogger<JwtTokenService> _logger;
        private readonly JwtOptions _jwtOptions;

        public JwtTokenService(UserManager<AppUser> userManager, IOptions<JwtOptions> jwtOptions, 
                                ILogger<JwtTokenService> logger)
        {
            _jwtOptions = jwtOptions.Value;
            _userManager = userManager;
            _logger = logger;
        }

        public async Task<TokenResponse> CreateTokenAsync(AppUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var keyBytes = Encoding.UTF8.GetBytes(_jwtOptions.Key!);
            var key = new SymmetricSecurityKey(keyBytes);
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()), 
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName!)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddSeconds(30),
                Issuer = _jwtOptions.Issuer,
                Audience = _jwtOptions.Audience,
                SigningCredentials = creds
            };

            var tokenHandler = new JsonWebTokenHandler();       
            var accessToken =  tokenHandler.CreateToken(tokenDescriptor);

            // ✅ Generate Refresh Token (random string)
            var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);  // valid for 7 days.
            await _userManager.UpdateAsync(user);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresAt = tokenDescriptor.Expires!.Value
            };


        }
    }
}
