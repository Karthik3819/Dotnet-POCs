using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ExceptionHandling.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class ExceptionController : ControllerBase
    {
        [HttpGet("{id}")]
        public IActionResult Getuser(int id)
        {
            if (id <= 0) throw new ArgumentException("Invalid user id.");
            if (id > 100) throw new KeyNotFoundException("User not found.");

            throw new Exception("Unexpected failure.");
        }
    }
}
