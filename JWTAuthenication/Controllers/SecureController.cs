using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthenication.Controllers
{
    [Route("api/secure")]
    [ApiController]
    public class SecureController : ControllerBase
    {
        [HttpGet("public")]
        [AllowAnonymous]
        public IActionResult PublicEndpoint() => Ok("Anyone can access this");

        [HttpGet("me")]
        [Authorize]
        public IActionResult Me() =>
            Ok(new {
                user = User.Identity.Name,
                roles = User.Claims.Where(c =>  c.Type == "role").Select(c => c.Value)
            });



        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly() => Ok("Admin endpoint");

        [HttpGet("manager")]
        [Authorize(Roles = "Manager")]
        public IActionResult ManagerOnly() => Ok("Manager endpoint");


        [HttpGet("reports")]
        [Authorize(Roles = "Admin,Manager")]
        public IActionResult Reports() => Ok("Reports for Admins and Managers");

    }
}
