using GoogleAndJwtToken.Dtos;
using FluentValidation;
using GoogleAndJwtToken.Common.Payloads.Requests;

namespace GoogleAndJwtToken.Validation
{
    public class SignupValidation : AbstractValidator<SignupRequest>
    {
        public SignupValidation()
        {
            RuleFor(x => x.UserName).NotEmpty().WithMessage("Username is required");
            RuleFor(x => x.Email).NotEmpty().WithMessage("Email is required")
                .EmailAddress().WithMessage("A valid email is required.");
            RuleFor(x => x.Phone).NotEmpty().WithMessage("Phone is required").
                Matches(@"^(0|\+84)\d{9}$").WithMessage("Invalid phone number format"); ;
            RuleFor(x => x.Address).NotEmpty().WithMessage("Address is required");
            RuleFor(x => x.Image).NotEmpty().WithMessage("Image is required");
            RuleFor(x => x.RoleId).NotEmpty().WithMessage("Role is required");
        }
    }
}
