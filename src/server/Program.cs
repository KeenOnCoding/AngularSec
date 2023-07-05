using IdentityServer4.Models;
using IdentityServer4;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
//var connectionString = builder.Configuration.GetConnectionString("ApplicationDbContextConnection") ?? throw new InvalidOperationException("Connection string 'ApplicationDbContextConnection' not found.");


var connectionString = "Server=(localdb)\\mssqllocaldb;Database=TestAppMvc;Trusted_Connection=True;MultipleActiveResultSets=true";
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(config => {
    //config.Password.RequireUppercase = true;
    //config.Password.RequireDigit = true;
    //config.Password.RequireNonAlphanumeric = true;
    //config.Password.RequiredLength = 6;
    //config.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+ ";

    //// Lockout settings
    //config.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    //config.Lockout.MaxFailedAccessAttempts = 3;
    //config.Lockout.AllowedForNewUsers = true;

    //// User settings
    //config.User.RequireUniqueEmail = true;
    //config.SignIn.RequireConfirmedAccount = false;
    //config.SignIn.RequireConfirmedEmail = true;
    //config.SignIn.RequireConfirmedPhoneNumber = false;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddIdentityServer()
    .AddAspNetIdentity<ApplicationUser>()
    .AddInMemoryApiResources(Configuration.GetApis())
    .AddInMemoryIdentityResources(Configuration.GetIdentityResources())
    .AddInMemoryClients(Configuration.GetClients())
    .AddDeveloperSigningCredential();
//builder.Services.AddAuthentication()
//               .AddJwtBearer();

builder.Services.AddCors(options =>
    options.AddPolicy("AllowAll",
                      builder => builder.WithOrigins("http://localhost:4200")
                          .AllowAnyMethod()
                          .AllowAnyHeader()));

builder.Services.ConfigureApplicationCookie(config =>
{
    config.Cookie.Name = "IdentityServer.Cookie";
    config.Cookie.HttpOnly = false;
    //config.Cookie.SameSite = SameSiteMode.Lax;
    config.LoginPath = "/Identity/Account/Login";
    config.LogoutPath = "/Identity/Account/Logout";
    //config.SlidingExpiration = true;
    // config.ExpireTimeSpan = TimeSpan.FromMinutes(30);
});


builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseIdentityServer();
app.UseHttpsRedirection();
app.UseStaticFiles();
if (app.Environment.IsDevelopment())
{
    app.UseCookiePolicy(new CookiePolicyOptions()
    {
        MinimumSameSitePolicy = SameSiteMode.Lax
    });
}
app.UseCors("AllowAll");  
app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
// app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

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
                new ApiResource("ApiOne"),
                new ApiResource("AcaServicesApi")
        };

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
                        $"{fEUrl}",
                    },
                    PostLogoutRedirectUris =
                    {
                        $"{fEUrl}",
                    },
                    AllowedCorsOrigins =
                    {
                        "http://localhost:4200",
                        "https://localhost:44305"
                    },

                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile
                       // IdentityServerConstants.StandardScopes.OfflineAccess
                        //"AcaServicesApi"
                    },

                    AccessTokenLifetime = 30,
                    IdentityTokenLifetime = 60,

                    AllowAccessTokensViaBrowser = true,
                    RequireConsent = false,
                }
        };
}
