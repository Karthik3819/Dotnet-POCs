using JWTAuthenication.Models;
using JWTAuthenication.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthenication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly JwtTokenService tokenService;


        public record LoginRequest(string Email, string Password);
        public AuthController(UserManager<AppUser> userManager,
                              RoleManager<IdentityRole> roleManager,
                              JwtTokenService tokenService)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(string email, string password, string role)
        {
            if (!await roleManager.RoleExistsAsync(role))
                return BadRequest("Role does not exist");

            var user = new AppUser { UserName = email, Email = email };

            var result = await userManager.CreateAsync(user, password);

            if (!result.Succeeded) return BadRequest(result.Errors);

            await userManager.AddToRoleAsync(user, role);

            return Ok(new { message = "User registered successfully", email, role });

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            var user = await userManager.FindByEmailAsync(loginRequest.Email);
            if (user == null) return Unauthorized("Invalid email.");

            if (!await userManager.CheckPasswordAsync(user, loginRequest.Password))
                return Unauthorized("Invalid password.");

            var token = await tokenService.CreateTokenAsync(user);

            return Ok(new { token });
        }


        [HttpPost("seed")]
        public async Task<IActionResult> Seed()
        {
            string[] roles = ["Admin", "Manager", "User"];

            foreach (var role in roles)
                if (!await roleManager.RoleExistsAsync(role))
                    await roleManager.CreateAsync(new IdentityRole(role));

            var admin = new AppUser { UserName = "admin@demo.com", Email = "admin@demo.com" };

            if(await userManager.FindByEmailAsync(admin.Email) == null)
            {
                await userManager.CreateAsync(admin,"Pass@123");
                await userManager.AddToRoleAsync(admin, "Admin");
            }

            return Ok(new { message = "seeded roles & admin user" });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            var user = await userManager.Users
                .SingleOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);

            if (user == null || user.RefreshTokenExpiry < DateTime.UtcNow)
                return Unauthorized("Invalid or expired refresh token");

            var tokens = await tokenService.CreateTokenAsync(user);
            return Ok(tokens);
        }


    }
}
