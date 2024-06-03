using AutoMapper;
using GoogleAndJwtToken.Dtos;
using GoogleAndJwtToken.Models;

namespace GoogleAndJwtToken.Mapper
{
    public class ApplicationMapper : Profile
    {
        public ApplicationMapper() 
        {
            CreateMap<User, UserModel>().ReverseMap();
        }
    }
}
