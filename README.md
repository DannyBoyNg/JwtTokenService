# JwtTokenService

A service to help manage JWT access tokens and refresh tokens in C#. Supports: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512.  
This package is a simple wrapper for Microsoft.IdentityModel.JsonWebTokens and aims to make managing JWT tokens as easy as possible.

## Dependancies

Microsoft.IdentityModel.JsonWebTokens  
Microsoft.Extensions.Options  

## Installing

Install from Nuget
```
Install-Package Ng.JwtTokenService
```

## Understanding claims, claimsIdentity and ClaimsPrincipal

Claims are key-value pairs that store information about a user (like userId, name, email, role). ClaimsIdentity is a collection of claims. A claimsPrincipal may contains one or more claimsIdentities.

## Usage

Breaking change: from version 9.0, this package uses the more modern Microsoft.IdentityModel.JsonWebTokens instead of System.IdentityModel.Tokens.Jwt. Because of this change certain functions will not work anymore. The compiler will generate an obsolete error for certain functions. To solve these errors use GenerateAccessTokenFromOldAccessTokenAsync instead of GenerateAccessTokenFromOldAccessToken, GetClaimsFromAccessTokenAsync instead of GetClaimsFromAccessToken and GetClaimsFromExpiredAccessTokenAsync instead of GetClaimsFromExpiredAccessToken.

Breaking change: from version 7.0, IRefreshTokenRepo has been removed in favor of a more simplified api. Storing and retrieving refresh tokens are not handled by this package anymore. Use the new function IsRefreshTokenExpired to determine if the refresh token is expired. This does not validate a refresh token. You must validate the refresh token yourself by storing the refresh token in a database and by checking if a refresh token belongs to a certain user.

Console application

```csharp
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Ng.JwtTokenService;
...

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
    SecurityAlgorithm = SecurityAlgorithm.HS256, //default: SecurityAlgorithm.HS256
    AccessTokenExpirationInMinutes = 60, //default: 60
    RefreshTokenExpirationInHours = 2, //default: 2
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
var jwtTokenService = new JwtTokenService(settings);

//Generate Access token
string accessToken = jwtTokenService.GenerateAccessToken(userName, roles, claims);

//Validate Access token and retrieve claims, Will throw exception if token is invalid or expired
ClaimsPrincipal claimsPrincipal = await jwtTokenService.GetClaimsFromAccessTokenAsync(accessToken);

//Get data from token/ClaimsPrincipal
string? userNameFromToken = jwtTokenService.GetUserName(claimsPrincipal);
string? userIdFromToken = jwtTokenService.GetClaim(claimsPrincipal, "userId");
string[]? rolesFromToken = jwtTokenService.GetRoles(claimsPrincipal);
List<Claim> allClaimsFromToken = jwtTokenService.GetAllClaims(claimsPrincipal).ToList();
List<Claim> userDefinedClaimsFromToken = jwtTokenService.GetUserDefinedClaims(claimsPrincipal).ToList();

//Lets say the access token has expired and you need to get data from it. This will still check if signature is valid on the token.
ClaimsPrincipal claimsPrincipalExpired = await jwtTokenService.GetClaimsFromExpiredAccessTokenAsync(accessToken); //Will throw exception if token is invalid, will not check if token has expired
string? userNameFromExpiredToken = jwtTokenService.GetUserName(claimsPrincipalExpired);

//Generate Refresh token. A refresh token is just a random string with a timestamp in it, you could generate this yourself also.
string refreshToken = jwtTokenService.GenerateRefreshToken();

//Check if the refresh token has expired.
if (jwtTokenService.IsRefreshTokenExpired(refreshToken)) throw new Exception("Refresh token expired");

//Generate new Access token with an old Access token. It copies all the user defined claims to the new token.
var newAccessToken = await jwtTokenService.GenerateAccessTokenFromOldAccessTokenAsync(accessToken);
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
Notes: It is recommended to store your asymmetric keys to a file and load them when your app starts. The main reason for this is that when you restart your web app, all the tokens that you have already issued will no longer work if you generate a new asymmetric key at startup. (You don't have to use a file, you could use any secure key provider)  

Use a console app to create a new private key and Copy the file over to your ASP.NET Core app root
```csharp
using var ECDsa = new ECDsaHelper();
var myKeyECDsaKey = ECDsa.CreateECDsaSecurityKey(ECDsaCurve.P521);
var keyString = ECDsaHelper.ECDsaSecurityKeyToPrivateKeyString(myKeyECDsaKey);
File.WriteAllText("ECDsaPrivateKey.txt", keyString);
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
    IssuerSigningKey = ECDsa.PrivateKeyStringToECDsaSecurityKey(File.ReadAllText("ECDsaPrivateKey.txt")),
    ValidateLifetime = true,
    SaveSigninToken = true,
};
```

The same can be done for RSA also
```csharp
using var RSA = new RsaHelper();
var myRSAKey = RSA.CreateRSASecurityKey();
var keyString = RsaHelper.RsaSecurityKeyToPrivateKeyString(myRSAKey);
File.WriteAllText("RsaPrivateKey.txt", keyString);
```
Then convert the file to a RSASecurityKey
```csharp
//If you dispose RSAHelper, all key material will be disposed. All generated SecurityKeys will also not work anymore.
//Only dispose if you don't need the generated keys anymore.
var RSA = new RsaHelper();
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = Configuration["JwtSettings:Issuer"], //Get settings from appsettings.json
    ValidateAudience = true,
    ValidAudience = Configuration["JwtSettings:Audience"],
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = RSA.PrivateKeyStringToRsaSecurityKey(File.ReadAllText("RsaPrivateKey.txt")),
    ValidateLifetime = true,
    SaveSigninToken = true,
};
```

If you need to load a private key from a pem encoded file, you would do something like this
```csharp
var pem = File.ReadAllText("PrivateKey.pem");
var rsa = RSA.Create();
rsa.ImportFromPem(pem.ToCharArray());
var securityKey = new RsaSecurityKey(rsa);

//JWT TokenValidationParameters
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = Configuration["JwtSettings:Issuer"], //Get settings from appsettings.json
    ValidateAudience = true,
    ValidAudience = Configuration["JwtSettings:Audience"],
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = securityKey, // <-- security key from pem encoded file
    ValidateLifetime = true,
    SaveSigninToken = true,
};
//JWT Settings
var settings = new JwtTokenSettings
{
    SecurityAlgorithm = SecurityAlgorithm.RS256,
    AccessTokenExpirationInMinutes = 60,
    RefreshTokenExpirationInHours = 2,
    TokenValidationParameters = tokenValidationParameters,
};
```

ASP.NET Core  

Add Services with dependency injection
Add UseAuthentication to Configure/Pipeline
```csharp
// This is just an example Configure/Pipeline. It doesn't need to look exactly like this. (Program.cs)
using Ng.JwtTokenService;
...
var builder = WebApplication.CreateBuilder(args);

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
builder.Services.AddJwtTokenService(options => {
    options.SecurityAlgorithm = SecurityAlgorithm.HS256;
    options.AccessTokenExpirationInMinutes = int.Parse(Configuration["JwtSettings:AccessTokenExpirationInMinutes"]); //Default: 60
    options.RefreshTokenExpirationInHours = int.Parse(Configuration["JwtSettings:RefreshTokenExpirationInHours"]); //Default: 2
    options.TokenValidationParameters = tokenValidationParameters;
});
builder.Services
    .AddAuthentication(options => {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options => options.TokenValidationParameters = tokenValidationParameters);

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication(); // <-- Add this to the pipeline

app.UseAuthorization();

app.MapControllers();

app.Run();
```

Create an Auth controller with Login/Refresh endpoints
```csharp
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
        //...
        //get roles for the user from data store
        var roles = new string[] { "Admin", "SuperUser" };
        //create claims
        var claims = new List<Claim> { new Claim("userId", user.Id.ToString()) };
        //create tokens
        var accessToken = jwtTokenService.GenerateAccessToken(user.UserName, roles, claims);
        var refreshToken = jwtTokenService.GenerateRefreshToken();
        //store refresh token in database
        //...
        return Ok(new JwtToken { AccessToken = accessToken, RefreshToken = refreshToken, TokenType = "bearer" });
    }

    //An example refresh endpoint
    public ActionResult Refresh(string accessToken, string refreshToken)
    {
        //get userId from access token
        var claimsPrincipal = jwtTokenService.GetClaimsFromExpiredAccessToken(accessToken);
        var userIdFromToken = jwtTokenService.GetClaim(claimsPrincipal, "userId");
        if (!int.TryParse(userIdFromToken, out int userId)) return Unauthorized("Invalid access token");

        //Determine if refresh token belongs to user
        //...

        //Check if refresh token is expired
        if(jwtTokenService.IsRefreshTokenExpired(refreshToken)) return Unauthorized("Expired refresh token");
        //create new tokens
        var newAccessToken = jwtTokenService.GenerateAccessTokenFromOldAccessToken(accessToken);
        var newRefreshToken = jwtTokenService.GenerateRefreshToken();
        //store new refresh token in database and remove old token. 
        //...
        return Ok(new JwtToken { AccessToken = newAccessToken, RefreshToken = newRefreshToken, TokenType = "bearer" });
    }
}
```

Protect an controller or action
```csharp
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
