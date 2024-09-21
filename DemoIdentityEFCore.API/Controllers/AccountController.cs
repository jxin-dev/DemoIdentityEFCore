using DemoIdentityEFCore.API.Requests;
using DemoIdentityEFCore.API.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace DemoIdentityEFCore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IJwtTokenService _jwtTokenService;


        public AccountController(UserManager<IdentityUser> userManager, IEmailService emailService, IJwtTokenService jwtTokenService)
        {
            _userManager = userManager;
            _emailService = emailService;
            _jwtTokenService = jwtTokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterAccountRequest request)
        {
            var newUser = new IdentityUser()
            {
                UserName = request.Email,
                Email = request.Email,
                PasswordHash = request.Password
            };
            var result = await _userManager.CreateAsync(newUser, request.Password);
            if (!result.Succeeded)
            {
                var error = result.Errors.First();
                return BadRequest(new { Code = error.Code, Description = error.Description });
            }

            await _userManager.SetTwoFactorEnabledAsync(newUser, true);

            return Ok(new { Message = "Account has been created!" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user is null)
            {
                return Unauthorized();
            }
            var isValidPassword = await _userManager.CheckPasswordAsync(user, request.Password);
            if(!isValidPassword)
            {
                return Unauthorized();
            }

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);

            var message = $"To complete your login process, please use this code: {token} as your verification.";
            await _emailService.SendEmailAsync(user.Email!, "2FA Verification", message);

            return Ok(new { Message = "2FA verification code sent to your email. Kindly check and verify." });
        }

        [HttpPost("verify2FA")]
        public async Task<IActionResult> Verify([FromQuery] string email, [FromQuery] string code)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return BadRequest();
            }
            var IsVerify = await _userManager.VerifyTwoFactorTokenAsync(user!, TokenOptions.DefaultEmailProvider, code);
            if (!IsVerify)
            {
                return Forbid();
            }
            var claimsIdentity = new ClaimsIdentity();
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Email, email),
            };
            claimsIdentity.AddClaims(claims);

            var token = _jwtTokenService.CreateSecurityToken(claimsIdentity);

            return Ok(new { Message = "Login successfully.", Token = _jwtTokenService.WriteToken(token) });
        }
    }
}
