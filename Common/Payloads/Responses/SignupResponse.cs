﻿namespace GoogleAndJwtToken.Common.Payloads.Responses
{
    public class SignupResponse
    {
        public string AccessToken { get; set; } = null!;    
        public string RefreshToken { get; set; } = null!;
    }
}
