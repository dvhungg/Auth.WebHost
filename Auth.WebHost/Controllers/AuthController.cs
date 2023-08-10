using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Auth.Ott.Abstractions.Interfaces;
using Auth.Ott.Abstractions.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Auth.WebHost.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        private IConfiguration _configuration;
        private IOneTimeTokenService _service;

        public AuthController(IOneTimeTokenService service, IConfiguration configuration)
        {
            _service = service;
            _configuration = configuration;
        }

        public const string DEFAULT_ROLE = "DefaultRole";

        [HttpGet("auth")]
        [AllowAnonymous]
        public async Task<IActionResult> Auth()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    //new Claim(ClaimTypes.Name, users.Name)
                }),
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return Ok(tokenHandler.WriteToken(token));
        }

        [HttpGet("get-ott")]
        [Authorize]
        public async Task<IActionResult> GetOneTimeToken()
            => Ok(_service.CreateToken(new Claim(ClaimTypes.Role, DEFAULT_ROLE)));

        [HttpGet("authentication")]
        //[Authorize(AuthenticationSchemes = "Bearer,Ott")]
        [Authorize]
        public async Task<IActionResult> RequireOneTimeTokenAuthentication([FromQuery] string accessToken)
            => Ok("Hello, you are authenticated");

        [HttpGet("authorization")]
        [Authorize(AuthenticationSchemes = OneTimeTokenDefaults.AuthenticationScheme, Roles = DEFAULT_ROLE)]
        public async Task<IActionResult> RequireOneTimeTokenAuthorization([FromQuery] string accessToken)
            => Ok("Hello, you are authorized");
    }
}