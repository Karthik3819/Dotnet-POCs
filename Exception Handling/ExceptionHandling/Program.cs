using ExceptionHandling;
using Microsoft.AspNetCore.Diagnostics;
using Serilog;


var builder = WebApplication.CreateBuilder(args);


Log.Logger = new LoggerConfiguration()
    .Enrich.FromLogContext()                            // add context info                                // log to console
    .WriteTo.File(
                    path: "logs/log-.json",                       // log to rolling files
                    rollingInterval:RollingInterval.Day,
                    formatter: new Serilog.Formatting.Json.JsonFormatter()
                    )                             // adjust level as needed
    .CreateLogger();


builder.Host.UseSerilog();   // replace default logger with Serilog



// Add services to the container.

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseMiddleware<ExceptionMiddleware>();

//app.UseExceptionHandler("/error");

//app.UseHttpsRedirection();

//app.UseAuthorization();

app.MapControllers();

//app.Map("/error", (HttpContext context) =>
//{
//    var exception = context.Features.Get<IExceptionHandlerFeature>()?.Error;

//    return Results.Problem(
//        title: "Unexpected error occurred",
//        detail: exception?.Message,
//        statusCode: 500
//    );
//});


app.Run();
