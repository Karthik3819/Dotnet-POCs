using JWTAuthenication.Models;
using JWTAuthenication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ✅ Enable logging system-wide (Console, Debug, etc.)
builder.Services.AddLogging();

// ✅ Register EF Core DbContext using InMemory provider (good for demos/testing)
//    In production, you’d use SQL Server, PostgreSQL, etc.
builder.Services.AddDbContext<AppDbContext>(opt =>
{
    opt.UseInMemoryDatabase("AuthDb");
});

// ✅ Register Controllers (API endpoints)
//    Adds support for [ApiController], routing, JSON serialization, etc.
builder.Services.AddControllers();

// ✅ Swagger (OpenAPI) setup
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    // Add metadata about the API
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });

    // 🔐 Add a Security Definition for JWT Bearer tokens
    // This makes the "Authorize" button appear in Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",                  // Header name
        Type = SecuritySchemeType.Http,          // Auth type
        Scheme = "Bearer",                       // Auto-prefix "Bearer " to token
        BearerFormat = "JWT",                    // Format
        In = ParameterLocation.Header,           // Where to expect it (HTTP header)
        Description = "Enter 'Bearer {your JWT token}'"
    });

    // 🔐 Add a global security requirement → applies Bearer auth to all endpoints
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"                // Must match above definition
                },
            },
            new List<string>()
        }
    });
});

// ✅ Register Identity (User + Role management)
// - AppUser = custom user model (extends IdentityUser)
// - IdentityRole = built-in role table
// - Uses EF Core with AppDbContext
builder.Services.AddIdentity<AppUser, IdentityRole>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>();

// ✅ Bind JwtOptions (Issuer, Audience, Key) from appsettings.json
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

// Extract JWT settings manually for TokenValidationParameters
var jwtSection = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSection["Key"]!);

// ✅ Configure Authentication Middleware (Default = JWT Bearer)
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;  // Who authenticates requests
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;    // What happens when unauthorized
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;             // General default
})
.AddJwtBearer(opt =>
{
    // ✅ Tell ASP.NET how to validate JWT tokens
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,                         // Ensure "iss" matches
        ValidateAudience = true,                       // Ensure "aud" matches
        ValidateIssuerSigningKey = true,               // Validate the secret/signature
        ValidateLifetime = true,                       // Check exp/nbf times
        ValidIssuer = jwtSection["Issuer"],
        ValidAudience = jwtSection["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero

    };

    // ✅ Optional: Hook into JWT events to log/debug token handling
    opt.Events = new JwtBearerEvents
    {
        // When the token arrives in the request
        OnMessageReceived = context =>
        {
            var auth = context.Request.Headers["Authorization"].ToString();
            if (!string.IsNullOrEmpty(auth) &&
                auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = auth.Substring("Bearer ".Length).Trim();
                token = token.Trim('"', '\''); // Remove accidental quotes
                var parts = token.Split('.');
                if (parts.Length == 3)
                {
                    context.Token = token; // ✅ set token to validate
                    Console.WriteLine($"[JwtBearer] Using token (len {token.Length}).");
                }
                else
                {
                    Console.WriteLine("[JwtBearer] Malformed token.");
                }
            }
            else
            {
                Console.WriteLine("[JwtBearer] No Bearer token found.");
            }
            return Task.CompletedTask;
        },

        // When token validation fails
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"[JwtBearer] Auth failed: {context.Exception}");
            return Task.CompletedTask;
        },

        // When token successfully validated
        OnTokenValidated = context =>
        {
            Console.WriteLine("[JwtBearer] Token validated.");
            return Task.CompletedTask;
        }
    };
});

// ✅ Add Authorization services
// Lets you use [Authorize], roles, policies
builder.Services.AddAuthorization();

// ✅ Register custom service for issuing JWTs
builder.Services.AddScoped<JwtTokenService>();


//✅ Allow CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngular",
        policy =>
        {
            policy.WithOrigins("http://localhost:4200") // 👈 Angular URL
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});

var app = builder.Build();

// ✅ Debug print JWT configuration
Console.WriteLine($"JWT Config: Issuer={jwtSection["Issuer"]}, Audience={jwtSection["Audience"]}, Key={jwtSection["Key"]}");

if (app.Environment.IsDevelopment())
{
    // ✅ Enable Swagger in Development only
    app.UseSwagger();
    app.UseSwaggerUI();
}

// ✅ Redirect HTTP → HTTPS
app.UseHttpsRedirection();

// ✅ Return proper status codes instead of blank responses
// (e.g., 401 Unauthorized, 403 Forbidden)
app.UseStatusCodePages();

// ✅ Debug: log Authorization header for every request
app.Use(async (context, next) =>
{
    var auth = context.Request.Headers["Authorization"].ToString();
    Console.WriteLine($"[AUTH HEADER] '{auth}'");
    await next();
});

app.UseCors("AllowAngular");

// ✅ Authentication middleware (validates JWT, sets HttpContext.User)
// Must come BEFORE Authorization
app.UseAuthentication();

// ✅ Authorization middleware (enforces [Authorize] attributes)
app.UseAuthorization();

// ✅ Map controller endpoints
app.MapControllers();

// ✅ Run the app
app.Run();
