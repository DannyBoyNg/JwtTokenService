# JwtTokenService

A service to help manage JWT access tokens and refresh tokens in C#. Supports: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512.  
This service is a simple wrapper for System.IdentityModel.Tokens.Jwt. Please use Bouncy Castle or other third party libraries if you need a more feature rich library. For example, System.IdentityModel.Tokens.Jwt does not have support for PEM encoded files. Bouncy Castle does have support for PEM encoded files.

## Dependancies

System.IdentityModel.Tokens.Jwt  
Microsoft.Extensions.Options  

## Installing

Install from Nuget
```
Install-Package Ng.JwtTokenService
```

## Usage

Console application

```csharp
using Microsoft.IdentityModel.Tokens;
using Ng.Services;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
...
//Example implementation of an inMemory repository for refresh tokens. In production, you would use a database
//store and not an inMemory store. Never use this in production.
IRefreshTokenRepository inMemoryRepository = new MyInMemoryRefreshTokenRepository();

//JWT TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    //Key cannot be shorter than 16 characters or it won't work
    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySuperDuperSecretSymmetricKey")),
    //Set this to false for Access tokens never to expire
    ValidateLifetime = true,
    SaveSigninToken = true,
};

//JWT Settings
var settings = new JwtTokenSettings
{
    //This algorithm can only be used in combination with SymmetricSecurityKey
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

//Validate Access token and retrieve claims, Will throw exception if token is invalid or expired
ClaimsPrincipal claimsPrincipal = jwtTokenService.GetClaimsFromAccessToken(accessToken);

//Get data from token
string userNameFromToken = jwtTokenService.GetUserName(claimsPrincipal);
string userIdFromToken = jwtTokenService.GetClaim(claimsPrincipal, "userId");
string[] rolesFromToken = jwtTokenService.GetRoles(claimsPrincipal);
List<Claim> allClaimsFromToken = jwtTokenService.GetAllClaims(claimsPrincipal).ToList();
List<Claim> userDefinedClaimsFromToken = jwtTokenService.GetUserDefinedClaims(claimsPrincipal).ToList();

//Get data from expired token. This will check if signature is valid on the token.
ClaimsPrincipal claimsPrincipalExpired = jwtTokenService.GetClaimsFromExpiredAccessToken(accessToken); //Will throw exception if token is invalid
string userNameFromExpiredToken = jwtTokenService.GetUserName(claimsPrincipalExpired);

//Generate Refresh token. A refresh token is just a random string, you could generate this yourself also.
string refreshToken = jwtTokenService.GenerateRefreshToken();

//These methods will throw an exception if no refreshToken repository is provided
jwtTokenService.StoreRefreshToken(userId, refreshToken);
jwtTokenService.ValidateRefreshToken(userId, refreshToken); //Will throw an exception if refresh token is not valid

//Generate new Access token with an old Access token. It copies all the user defined claims to the new token.
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
    SecurityAlgorithm = SecurityAlgorithm.HS256, // <-- Options: HS256, HS384, HS512
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```
RSA Key (RS256, RS384, RS512)
```csharp
//JWT TokenValidationParameters
//If you dispose RsaHelper, all key material will be disposed. All generated SecurityKeys will also not work anymore.
//Only dispose if you don't need the generated keys anymore.
var rsa = new RsaHelper(); 
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = rsa.CreateRSASecurityKey(), // <-- RSA Key
    ValidateLifetime = true,
    SaveSigninToken = true,
};
//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.RS256, // <-- Options: RS256, RS384, RS512
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```
ECDsa Key (ES256, ES384, ES512)
```csharp
//JWT TokenValidationParameters
//If you dispose ECDsaHelper, all key material will be disposed. All generated SecurityKeys will also not work anymore.
//Only dispose if you don't need the generated keys anymore.
var ECDsa = new ECDsaHelper(); 
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "me",
    ValidateAudience = true,
    ValidAudience = "you",
    ValidateIssuerSigningKey = true,
    //ECDsa Key. Curve options: P256 (default), P384, P521. Default is used if none is provided.
    IssuerSigningKey = ECDsa.CreateECDsaSecurityKey(ECDsaCurve.P256), 
    ValidateLifetime = true,
    SaveSigninToken = true,
};
//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.ES256, // <-- Options: ES256, ES384, ES512
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```
Notes: It is recommended to store your asymmetric keys to a file and load them when your app starts. The main reason for this is that when you restart your web app, all the tokens that you have already issued will no longer work if you generate a new asymmetric key at startup. (You don't have to use a file, you could any secure key provider)  

Use a console app to create a new private key and Copy the file over to your ASP.NET Core app root
```csharp
using var ECDsa = new ECDsaHelper();
var myKeyECDsaKey = ECDsa.CreateECDsaSecurityKey(ECDsaCurve.P521);
var keyString = ECDsaHelper.ECDsaSecurityKeyToPrivateKeyString(myKeyECDsaKey);
File.WriteAllText("ECDsaKeyPriv.txt", keyString);
```
Then convert the file to a ECDsaSecurityKey
```csharp
//If you dispose ECDsaHelper, all key material will be disposed. All generated SecurityKeys will also not work anymore.
//Only dispose if you don't need the generated keys anymore.
var ECDsa = new ECDsaHelper();
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = Configuration["JwtSettings:Issuer"], //Get settings from appsettings.json
    ValidateAudience = true,
    ValidAudience = Configuration["JwtSettings:Audience"],
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = ECDsa.PrivateKeyStringToECDsaSecurityKey(File.ReadAllText("ECDsaKeyPriv.txt")),
    ValidateLifetime = true,
    SaveSigninToken = true,
};
```

ASP.NET Core  

Register service with dependency injection in Startup.cs
```csharp
using Ng.Services;
...
public void ConfigureServices(IServiceCollection services)
{
    var tokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = Configuration["JwtSettings:Issuer"], //Get settings from appsettings.json
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
    //Also make sure you provide your own implementation of a RefreshToken repository. You don't have to provide a IRefreshTokenRepository,
    //if you don't plan on using refreshing tokens. Do not use (in-memory store) in production
    services.AddScoped<IRefreshTokenRepository, MyInMemoryRefreshTokenRepository>();
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
using Ng.Services;
...
[Route("api/[controller]/[action]")]
public class AuthController : ControllerBase
{
    private readonly IJwtTokenService jwtTokenService;

    public AuthController(IJwtTokenService jwtTokenService) // <-- Inject IJwtTokenService here
    {
        this.jwtTokenService = jwtTokenService;
    }

    //An example login endpoint. Make sure this endpoint is only callable from https
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
        var claimsPrincipal = jwtTokenService.GetClaimsFromExpiredAccessToken(accessToken);
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
using Ng.Services;
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
