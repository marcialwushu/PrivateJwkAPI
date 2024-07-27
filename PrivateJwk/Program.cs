using Microsoft.AspNetCore.Hosting;
using OpenTelemetry.Logs;
using OpenTelemetry;

namespace PrivateJwk
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                })
            .ConfigureLogging((hostingContext, logging) =>
                {
                    logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                    logging.AddConsole();
                    logging.AddDebug();

                    // Configuração de Logs com OpenTelemetry e exportação JSON
                    logging.AddOpenTelemetry(options =>
                    {
                        options.AddProcessor(new SimpleLogRecordExportProcessor(new JsonConsoleExporter<LogRecord>()));
                    });
                })
             .ConfigureServices(services =>
                {
                    services.AddOpenTelemetry().WithTracing();
                    services.AddOpenTelemetry().WithMetrics();
                });
    }
}
