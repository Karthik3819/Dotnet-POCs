using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace ExceptionHandling
{
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionMiddleware> _logger;

        public ExceptionMiddleware(RequestDelegate next, ILogger<ExceptionMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception occurred while processing {Path}", context.Request.Path);

                await HandleExceptionAsync(context, ex);
            }
        }

        public static Task HandleExceptionAsync(HttpContext context, Exception ex)
        {
            var statusCode = (int)HttpStatusCode.InternalServerError; // default 500


            //custom error mapping.
            if (ex is ArgumentException) { statusCode = (int)HttpStatusCode.BadRequest; }

            else if (ex is KeyNotFoundException) { statusCode = (int)HttpStatusCode.NotFound; }


            var problem = new ProblemDetails
            {
                Status = statusCode,
                Title = "An error occured while processing your request",
                Detail = ex.Message,
                Instance = context.Request.Path
            };

            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json";
            return context.Response.WriteAsJsonAsync(problem);
        }
    }
}
