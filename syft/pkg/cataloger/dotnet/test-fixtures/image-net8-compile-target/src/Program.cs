using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;

namespace HelloWorld
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            // configure the HTTP request pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
            }

            // enable serving static files (including jQuery)
            app.UseStaticFiles();

            app.MapGet("/", () => "Hello World!");

            Console.WriteLine("Application starting...");
            app.Run();
        }
    }
}
