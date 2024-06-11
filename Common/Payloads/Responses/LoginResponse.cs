namespace GoogleAndJwtToken.Common.Payloads.Responses;

public class LoginResponse
{
    public string AccessToken { get; set; } = null!;

    public string RefreshToken { get; set; } = null!;
}