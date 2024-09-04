using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtTokenBasedApi
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController: ControllerBase
    {
        private readonly IJWTManagerRepository _jwtManagerRepository;
        public UsersController(IJWTManagerRepository jwtManagerRepository)
        {
            _jwtManagerRepository = jwtManagerRepository;
        }

        [HttpGet]
        public List<string> Get()
        {
            var users = new List<string>
            {
                "User Test 1",
                "User Test 2",
                "User Test 3"
            };
            return users;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("authenticate")]
        public IActionResult Authenticate(Users user)
        {
            var token = _jwtManagerRepository.Authenticate(user);
            if (token == null) { 
                return Unauthorized();
            }
            return Ok(token);
        }

    }
}
