
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using OpenTelemetry.Metrics;
using OpenTelemetry.Logs;
using OpenTelemetry;
using System.Diagnostics;
using Microsoft.Extensions.Options;

namespace PrivateJwk
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers()
                    .AddNewtonsoftJson(options =>
                    {
                        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
                        options.SerializerSettings.ContractResolver = new DefaultContractResolver
                        {
                            NamingStrategy = new CamelCaseNamingStrategy()
                        };
                    });

            // Adicionar o serviço de logging
            services.AddLogging(builder =>
            {
                builder.ClearProviders();
                builder.AddConsole();
                builder.AddOpenTelemetry(options =>
                {
                    options.AddProcessor(new SimpleLogRecordExportProcessor(new JsonConsoleExporter<LogRecord>()));
                });
            });

            //// Registro do DiagnosticConfig
            //services.Configure<DiagnosticConfig>(Configuration.GetSection("DiagnosticConfig"));
            //services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<DiagnosticConfig>>().Value);



            // Configuração de Traces
            services.AddOpenTelemetry()
                .ConfigureResource(resource => resource.AddService("PrivateJwkTraces"))
                .WithTracing(tracing => tracing
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddSource("PrivateJwk")
                    .SetSampler(new AlwaysOnSampler())
                    .AddProcessor(new SimpleActivityExportProcessor(new JsonConsoleExporter<Activity>()))
                );

            // Configuração de Métricas
            services.AddOpenTelemetry()
                .WithMetrics(meter => meter
                    .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("PrivateJwkServiceMetrics"))
                    .AddAspNetCoreInstrumentation()
                    .AddHttpClientInstrumentation()
                    .AddMeter("Microsoft.AspNetCore.Hosting")
                    .AddMeter("Microsoft.AspNetCore.Server.Kestrel")
                    .AddMeter(DiagnosticConfig.Meter.Name)
                    .AddReader(new PeriodicExportingMetricReader(new JsonConsoleExporter<Metric>()))
                );
        }



        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
