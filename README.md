# JwtTokenService

A service to help manage JWT access tokens and refresh tokens in C#. Supports: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512.  
This service is a simple wrapper for Microsoft.IdentityModel.Tokens.Jwt. Please use Bouncy Castle or other third party libraries if you need a more feature rich library. For example, Microsoft.IdentityModel.Tokens.Jwt does not have support for PEM encoded files. Bouncy Castle does have support for PEM encoded files.

## Dependancies

Microsoft.IdentityModel.Tokens.Jwt  
Microsoft.Extensions.Options  

## Installing

Install from Nuget
```
Install-Package DannyBoyNg.JwtTokenService
```

## Usage

Console application

```csharp
using DannyBoyNg.Services;
...
//Example implementation of an inMemory repository for refresh tokens. In production, you would use a database store and not an inMemory store.
IRefreshTokenRepository inMemoryRepository = new MyInMemoryRefreshTokenRepository(); //Never use this in production

//JWT TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySuperDuperSecretSymmetricKey")),
    ValidateLifetime = true, //Set this to false for Access tokens never to expire
    SaveSigninToken = true,
};

//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.HS256,
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};

//My claims
var userName = "MyUserName";
var userId = 1;
var claims = new List<Claim> {
    new Claim("userId", userId.ToString()),
    new Claim("claim1", "value1"),
    new Claim("claim2", "value2"),
};

//get roles for the user from data store
var roles = new string[] { "Admin", "SuperUser" };

//Instantiate JWT service
var jwtTokenService = new JwtTokenService(settings, inMemoryRepository);

//Generate Access token
string accessToken = jwtTokenService.GenerateAccessToken(userName, roles, claims);

//Validate Access token
ClaimsPrincipal claimsPrincipal = jwtTokenService.GetPrincipalFromAccessToken(accessToken); //Will throw exception if token is invalid or expired

//Get data from token
string userNameFromToken = jwtTokenService.GetUserName(claimsPrincipal);
string userIdFromToken = jwtTokenService.GetClaim(claimsPrincipal, "userId");
string[] rolesFromToken = jwtTokenService.GetRoles(claimsPrincipal);
List<Claim> allClaimsFromToken = jwtTokenService.GetAllClaims(claimsPrincipal);
List<Claim> userDefinedClaimsFromToken = jwtTokenService.GetUserDefinedClaims(claimsPrincipal);

//Get data from expired token
ClaimsPrincipal claimsPrincipalExpired = jwtTokenService.GetPrincipalFromExpiredAccessToken(accessToken); //Will throw exception if token is invalid
string userNameFromExpiredToken = jwtTokenService.GetUserName(claimsPrincipalExpired);

//Generate Refresh token
string refreshToken = jwtTokenService.GenerateRefreshToken();

//These methods will throw an exception if no refreshToken repository is provided
jwtTokenService.StoreRefreshToken(userId, refreshToken);
jwtTokenService.ValidateRefreshToken(userId, refreshToken); //Will throw an exception if refresh token is not valid

//Generate new Access token with an old Access token
var newAccessToken = jwtTokenService.GenerateAccessTokenFromOldAccessToken(accessToken);
```

Example of an inMemory refreshToken repository (never use in production)

```csharp
public class MyInMemoryRefreshTokenRepository : IRefreshTokenRepository
{
    static readonly List<IRefreshToken> inMemStore = new List<IRefreshToken>();

    public void Delete(IRefreshToken refreshToken)
    {
        var item = inMemStore.Where(x => x.Token == refreshToken.Token && x.UserId == refreshToken.UserId).SingleOrDefault();
        if (item != null) inMemStore.Remove(item);
    }

    public void DeleteAll(int userId)
    {
        inMemStore.Clear();
    }

    public IEnumerable<IRefreshToken> GetByUserId(int userId)
    {
        return inMemStore.Where(x => x.UserId == userId);
    }

    public void Insert(int userId, string refreshToken)
    {
        inMemStore.Add(new RefreshToken { UserId = userId, Token = refreshToken });
    }
}

public class RefreshToken : IRefreshToken
{
    public string Token { get; set; }
    public int UserId { get; set; }
}
```

Use different Signing algorithms  
Symmetric Key (HS256, HS384, HS512)
```csharp
//JWT TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySuperDuperSecretSymmetricKey")), // <-- Symmetric Key
    ValidateLifetime = true,
    SaveSigninToken = true,
};
//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.HS256, // <-- Options: HS256, HS256, HS512
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```
RSA Key (RS256, RS384, RS512)
```csharp
//JWT TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = RsaHelper.CreateRSASecurityKey(), // <-- RSA Key
    ValidateLifetime = true,
    SaveSigninToken = true,
};
//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.RS256, // <-- Options: RS256, RS256, RS512
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```
ECDsa Key (ES256, ES384, ES512)
```csharp
//JWT TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = ECDsaHelper.CreateECDsaSecurityKey(ECDsaCurve.P256), // <-- ECDsa Key. Curve options: P256 (default), P384, P521
    ValidateLifetime = true,
    SaveSigninToken = true,
};
//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.ES256, // <-- Options: ES256, ES256, ES512
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```
Notes: It is recommended to store your asymmetric keys to a file and load them when your app starts. The main reason for this is that when you restart your web app, all the tokens that you have already issued will no longer work if you generate a new asymmetric key at startup. (You don't have to use a file, you could any secure key provider)  

Use a console app to create a new private key and Copy the file over to your ASP.NET Core app root
```csharp
var myKeyECDsaKey = ECDsaHelper.CreateECDsaSecurityKey(ECDsaCurve.P521);
var keyString = ECDsaHelper.ECDsaSecurityKeyToPrivateKeyString(myKeyECDsaKey);
File.WriteAllText("ECDsaKeyPriv.txt", keyString);
```
Then convert the file to a ECDsaSecurityKey
```csharp
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = Configuration["JwtSettings:Issuer"],
    ValidateAudience = true,
    ValidAudience = Configuration["JwtSettings:Audience"],
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = ECDsaHelper.PrivateKeyStringToECDsaSecurityKey(File.ReadAllText("ECDsaKeyPriv.txt")),
    ValidateLifetime = true,
    SaveSigninToken = true,
};
```

ASP.NET Core  

Register service with dependency injection in Startup.cs
```csharp
using DannyBoyNg.Services;
...
public void ConfigureServices(IServiceCollection services)
{
    var tokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = Configuration["JwtSettings:Issuer"],
        ValidateAudience = true,
        ValidAudience = Configuration["JwtSettings:Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JwtSettings:Key"])),
        ValidateLifetime = true,
        SaveSigninToken = true,
    };
    services.AddJwtTokenService(options => {
        options.SecurityAlgorithm = SecurityAlgorithm.HS256;
        options.AccessTokenExpirationInMinutes = int.Parse(Configuration["JwtSettings:AccessTokenExpirationInMinutes"]); //Default: 60
        options.RefreshTokenExpirationInHours = int.Parse(Configuration["JwtSettings:RefreshTokenExpirationInHours"]); //Default: 2
        options.TokenValidationParameters = tokenValidationParameters;
    });
    services
        .AddAuthentication(options => {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options => options.TokenValidationParameters = tokenValidationParameters);
    //Also make sure you provide your own implementation of a RefreshToken repository. You don't have to provide a IRefreshTokenRepository, if you don't plan on using refreshing tokens.
    services.AddScoped<IRefreshTokenRepository, MyInMemoryRefreshTokenRepository>(); //Do not use in production
}
```

Add UseAuthentication to Configure/Pipeline
```csharp
// This is just an example Configure/Pipeline. It doesn't need to look exactly like this.
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }

    app.UseHttpsRedirection();

    app.UseRouting();

    app.UseCors("CorsPolicy");

    app.UseAuthentication(); // <-- Add this to the pipeline

    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```

Create an Auth controller with Login/Refresh endpoints
```csharp
using DannyBoyNg.Services;
...
[Route("api/[controller]/[action]")]
public class AuthController : ControllerBase
{
    private readonly IJwtTokenService jwtTokenService;

    public AuthController(IJwtTokenService jwtTokenService) // <-- Inject IJwtTokenService here
    {
        this.jwtTokenService = jwtTokenService;
    }

    //An example login endpoint
    public ActionResult Token(string username, string password)
    {
        //get user from data store
        var user = new User
        {
            Id = 1,
            UserName = "MyUser",
            PasswordHash = "..."
        };
        //validate password. Do not continue if password is not valid

        //get roles for the user from data store
        var roles = new string[] { "Admin", "SuperUser" };
        //create claims
        var claims = new List<Claim> { new Claim("userId", user.Id.ToString()) };
        //create tokens
        var accessToken = jwtTokenService.GenerateAccessToken(user.UserName, roles, claims);
        var refreshToken = jwtTokenService.GenerateRefreshToken();
        //store refresh token
        jwtTokenService.StoreRefreshToken(user.Id, refreshToken);
        return Ok(new JwtToken { AccessToken = accessToken, RefreshToken = refreshToken, TokenType = "bearer" });
    }

    //An example refresh endpoint
    public ActionResult Refresh(string accessToken, string refreshToken)
    {
        //get userId from access token
        var claimsPrincipal = jwtTokenService.GetPrincipalFromExpiredAccessToken(accessToken);
        var userIdFromToken = jwtTokenService.GetClaim(claimsPrincipal, "userId");

        if (!int.TryParse(userIdFromToken, out int userId)) return Unauthorized("Invalid access token");
        //validate refresh token
        jwtTokenService.ValidateRefreshToken(userId, refreshToken);
        //create new tokens
        var newAccessToken = jwtTokenService.GenerateAccessTokenFromOldAccessToken(accessToken);
        var newRefreshToken = jwtTokenService.GenerateRefreshToken();
        //store refresh token in data store
        jwtTokenService.StoreRefreshToken(userId, newRefreshToken);
        return Ok(new JwtToken { AccessToken = newAccessToken, RefreshToken = newRefreshToken, TokenType = "bearer" });
    }
}
```

Protect an controller or action
```csharp
using DannyBoyNg.Services;
...
[Authorize]
[Route("members")]
public class MembersController : ControllerBase
{
    public async Task<ActionResult> Index()
    {
        //Get userName
        string username = User?.Identity?.Name;

        //Get claims
        IEnumerable<Claim> claims = User?.Claims;

        //Get access token
        string accessToken = await HttpContext.GetTokenAsync("access_token");

        //Only users with a valid token can get here
        return Ok($"Only logged in users can see this page. User: {username}");
    }
}

[Authorize(Roles = "Admin")]
[Route("admin")]
public class AdminController : ControllerBase
{
    public ActionResult Index()
    {
        //Only users with a valid token and have the role admin can get here
        return Ok("Only admins can see this page.");
    }
}
```

Add some settings to appsettings.json configuration file
```javascript
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "JwtSettings": {
    "Issuer": "localhost:44342", //Change to the location of the server issuing the token
    "Audience": "localhost:4200", //Change to the location of the client
    "Key": "MySuperDuperSymmetricSecretKey", //Your symmetric secret key. Do not commit this to GitHub. 
    "AccessTokenExpirationInMinutes": "30", //Don't forget there is like a 5 min clock skew built into ASP.NET Core
    "RefreshTokenExpirationInHours":  "1"
  }
}
```

## License

This project is licensed under the MIT License.

## Contributions

Contributions are welcome.
