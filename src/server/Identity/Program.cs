using IdentityServer4.Models;
using IdentityServer4;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using IdentityModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

var connectionString = "Server=(localdb)\\mssqllocaldb;Database=TestAppMvc;Trusted_Connection=True;MultipleActiveResultSets=true";
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(config => {
    /*

     config.Password.RequireUppercase = true;
     config.Password.RequireDigit = true;
     config.Password.RequireNonAlphanumeric = true;
     config.Password.RequiredLength = 6;
     config.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+ ";

     //// Lockout settings
     config.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
     config.Lockout.MaxFailedAccessAttempts = 3;
     config.Lockout.AllowedForNewUsers = true;

     //// User settings
     config.user.requireuniqueemail = true;
     config.signin.requireconfirmedaccount = false;
     config.signin.requireconfirmedemail = true;
     config.signin.requireconfirmedphonenumber = false;
    */
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddIdentityServer(options => {
    options.IssuerUri = "null";
    options.Authentication.CookieLifetime = TimeSpan.FromHours(2);
})
    .AddInMemoryIdentityResources(Configuration.GetIdentityResources())
    .AddInMemoryApiScopes(Configuration.GetApiScopes())
    .AddInMemoryApiResources(Configuration.GetApis())
    .AddInMemoryClients(Configuration.GetClients())
    .AddAspNetIdentity<ApplicationUser>()
    .AddDeveloperSigningCredential();

builder.Services.AddAuthentication()
     .AddGoogle(options =>
     {
         options.ClientId = "117295608902-i7ibrso0s6v45cc7qlemcikqdkd3ualo.apps.googleusercontent.com";
         options.ClientSecret = "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";
     })
    .AddGitHub(o =>
    {
        //  Add github:clientId and github:clientSecret to Project User Secrets
        // dotnet user-secrets set github:clientId "557384cccfcf5e412237"
        // dotnet user-secrets set github:clientSecret "ebb1d48446845f54c3bbbb98e6548cab10d6c709"


        o.ClientId = "557384cccfcf5e412237";
        o.ClientSecret = "ebb1d48446845f54c3bbbb98e6548cab10d6c709";
        o.CallbackPath = "/signin-github";

        // Grants access to read a user's profile data.
        // https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps
        o.Scope.Add("read:user");

        // Optional
        // if you need an access token to call GitHub Apis
        o.Events.OnCreatingTicket += context =>
        {
            if (context.AccessToken is { })
            {
                context.Identity?.AddClaim(new Claim("access_token", context.AccessToken));
            }

            return Task.CompletedTask;
        };
    }); ;

/*
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.Authority = "https://localhost:44305"; // base-address of your identityserver
                    options.TokenValidationParameters.ValidateAudience = false;
                    options.TokenValidationParameters.ValidTypes = new[] { "at+jwt" };
                    options.MapInboundClaims = false;
                    //options.TokenValidationParameters.NameClaimType = JwtClaimTypes.Name;
                    //options.TokenValidationParameters.RoleClaimType = JwtClaimTypes.Role;
                })
                

    .AddGoogle(options =>
    {
        options.ClientId = "117295608902-i7ibrso0s6v45cc7qlemcikqdkd3ualo.apps.googleusercontent.com";
        options.ClientSecret = "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";
    })
    .AddGitHub(o =>
    {
        //  Add github:clientId and github:clientSecret to Project User Secrets
        // dotnet user-secrets set github:clientId "557384cccfcf5e412237"
        // dotnet user-secrets set github:clientSecret "ebb1d48446845f54c3bbbb98e6548cab10d6c709"


        o.ClientId = "557384cccfcf5e412237";
        o.ClientSecret = "ebb1d48446845f54c3bbbb98e6548cab10d6c709";
        o.CallbackPath = "/signin-github";

        // Grants access to read a user's profile data.
        // https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps
        o.Scope.Add("read:user");

        // Optional
        // if you need an access token to call GitHub Apis
        o.Events.OnCreatingTicket += context =>
        {
            if (context.AccessToken is { })
            {
                context.Identity?.AddClaim(new Claim("access_token", context.AccessToken));
            }

            return Task.CompletedTask;
        };
    });
*/

//builder.Services.AddCors(options =>options.AddPolicy("AllowAll",builder => builder.AllowCredentials().WithOrigins("http://localhost:4200").SetIsOriginAllowedToAllowWildcardSubdomains().AllowAnyMethod().AllowAnyHeader()));

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        builder => builder
        .SetIsOriginAllowed((host) => true)
        .AllowAnyMethod()
        .AllowAnyHeader()
        .AllowCredentials());
});

builder.Services.ConfigureApplicationCookie(config =>
{

   // config.Cookie.Name = "IdentityServer.Cookie";
   config.Cookie.HttpOnly = false;
    config.Cookie.SameSite = SameSiteMode.Lax;
    config.LoginPath = "/Identity/Account/Login";
    config.LogoutPath = "/Identity/Account/Logout";
    //config.SlidingExpiration = true;
    // config.ExpireTimeSpan = TimeSpan.FromMinutes(30);
});

/*
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});
*/
builder.Services.AddControllersWithViews();

builder.Services.AddRazorPages();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseCookiePolicy(new CookiePolicyOptions { MinimumSameSitePolicy = SameSiteMode.Lax });

app.UseRouting();

app.UseIdentityServer();

app.UseAuthorization();

app.UseCors("CorsPolicy");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();
public class ApplicationUser : IdentityUser { }
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}
public static class Configuration
{
    private readonly static string fEUrl = "http://localhost:4200";
    public static IEnumerable<IdentityResource> GetIdentityResources() =>
        new List<IdentityResource>
        {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
        };

    public static IEnumerable<ApiResource> GetApis() =>
        new List<ApiResource> {
                //new ApiResource("ApiOne"),
                new ApiResource("vacancy", "Vacancies Service")
                //new ApiResource("AcaServicesApi")
        };

    // ApiScope is used to protect the API 
    //The effect is the same as that of API resources in IdentityServer 3.x
    public static IEnumerable<ApiScope> GetApiScopes()
    {
        return new List<ApiScope>
        {
            new ApiScope("vacancy", "Vacancies Service")
        };
    }
    public static IEnumerable<Client> GetClients() =>
        new List<Client> {
                new Client {
                    ClientId = "FreeFile-FE",              
                    AllowedGrantTypes = new List<string> { GrantType.AuthorizationCode },
                    RequirePkce = true,
                    RequireClientSecret = false,
                    UpdateAccessTokenClaimsOnRefresh = true,
                    RedirectUris =
                    {
                        $"{fEUrl}",
                        //$"{fEUrl}",
                    },
                    PostLogoutRedirectUris =
                    {
                        $"{fEUrl}",
                    },
                    AllowedCorsOrigins =
                    {
                        "http://localhost:4200"
                       // "https://localhost:44305"
                    },

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "vacancy"
                    },

                    AccessTokenLifetime = 3600,
                    IdentityTokenLifetime = 3600,

                    AllowAccessTokensViaBrowser = true,
                    RequireConsent = false,
                }
        };
}
public static class ClaimsExtensions
{
    public static string? FirstClaim(this IEnumerable<Claim>? claims, string type)
    {
        return claims?
            .Where(c => c.Type == type)
            .Select(c => c.Value)
            .FirstOrDefault();
    }

    public static string? AccessToken(this ClaimsPrincipal principal) =>
        principal.Claims.FirstClaim("access_token");
}