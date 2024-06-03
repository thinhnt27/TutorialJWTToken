using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using GoogleAndJwtToken.Common.Payloads.Requests;
using GoogleAndJwtToken.Common.Payloads.Responses;
using GoogleAndJwtToken.Exceptions;
using GoogleAndJwtToken.Service;
using GoogleAndJwtToken.Dtos;
using FluentValidation;
using GoogleAndJwtToken.Validation;
using GoogleAndJwtToken.Common;

namespace GoogleAndJwtToken.Controllers;

[Route("api/[controller]/[action]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IdentityService _identityService;
    private readonly IValidator<SignupRequest> _signupValidator;

    public AuthController(IdentityService identityService, IValidator<SignupRequest> signupValidator)
    {
        _identityService = identityService;
        _signupValidator = signupValidator;
    }

    
    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Signup([FromBody] SignupRequest req)
    {
        var validationResult = await _signupValidator.ValidateAsync(req);
        if (validationResult.IsValid)
        {
            var handler = new JwtSecurityTokenHandler();
            var res = await _identityService.Signup(req);
            if (!res.Authenticated)
            {
                var resultFail = new SignupResponse
                {
                    AccessToken = "Sign up fail"
                };
                return BadRequest(ApiResult<SignupResponse>.Succeed(resultFail));
            }
            var result = new SignupResponse
            {
                AccessToken = handler.WriteToken(res.Token)
            };

            return Ok(ApiResult<SignupResponse>.Succeed(result));
        }
        else
        {
            return BadRequest(validationResult.ToProblemDetails());
        }
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        var loginResult = _identityService.Login(req.UserName, req.Password);
        if (!loginResult.Authenticated)
        {
            var result = ApiResult<Dictionary<string, string[]>>.Fail(new Exception("Username or password is invalid"));
            return BadRequest(result);
        }

        var handler = new JwtSecurityTokenHandler();
        var res = new LoginResponse
        {
            AccessToken = handler.WriteToken(loginResult.Token),
        };
        return Ok(ApiResult<LoginResponse>.Succeed(res));
    }

    //get all users
    [HttpGet]
    [Authorize]
    public IActionResult GetAllUsers()
    {
        var users = _identityService.GetAllUsers();
        return Ok(ApiResult<List<UserModel>>.Succeed(users));
    }
}