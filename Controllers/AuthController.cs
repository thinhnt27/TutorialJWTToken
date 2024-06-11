using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GoogleAndJwtToken.Common.Payloads.Requests;
using GoogleAndJwtToken.Common.Payloads.Responses;
using GoogleAndJwtToken.Service;
using GoogleAndJwtToken.Dtos;
using GoogleAndJwtToken.Common;

namespace GoogleAndJwtToken.Controllers;

[Route("api/[controller]/[action]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IdentityService _identityService;

    public AuthController(IdentityService identityService)
    {
        _identityService = identityService;
    }


    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Signup([FromBody] SignupRequest req)
    {

        var handler = new JwtSecurityTokenHandler();
        var res = await _identityService.Signup(req);
        if (!res.Authenticated)
        {

            var resultFail = ApiResult<Dictionary<string, string[]>>.Fail(new Exception("Sign up fail"));
            return BadRequest(resultFail);
        }
        var result = new SignupResponse
        {
            AccessToken = handler.WriteToken(res.Token),
            RefreshToken = handler.WriteToken(res.RefreshToken)
        };

        return Ok(ApiResult<SignupResponse>.Succeed(result));

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
            RefreshToken = handler.WriteToken(loginResult.RefreshToken)
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