using System;
using Serilog;

namespace HelloWorld
{
    /// <summary>
    /// Main program class!
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Entry point for the application!
        /// </summary>
        /// <param name="args">Command line arguments!</param>
        public static void Main(string[] args)
        {
            // configure Serilog
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .WriteTo.Console()
                .CreateLogger();

            try
            {
                Log.Information("Starting up the application");
                Console.WriteLine("Hello World!");
                Log.Information("Application completed successfully");
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
