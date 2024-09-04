namespace JwtTokenBasedApi
{
    public interface IJWTManagerRepository
    {
        Tokens Authenticate(Users user);
    }
}
