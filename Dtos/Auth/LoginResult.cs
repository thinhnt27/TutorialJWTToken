using Microsoft.IdentityModel.Tokens;

namespace GoogleAndJwtToken.Dtos.Auth;

public class LoginResult
{
    public bool Authenticated { get; set; }
    public SecurityToken? Token { get; set; }

    public SecurityToken? RefreshToken { get; set; }
}