using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace PrivateJwk.Controllers
{
    [ApiController]
    [Route("api/certificate")]
    public class CertificateController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly DiagnosticConfig _diagnosticConfig;
        private readonly ILogger<CertificateController> _logger;
        private static readonly Meter Meter = new Meter("PrivateCertificate.Metrics", "1.0.0");
        private static readonly Counter<int> RequestCounter = Meter.CreateCounter<int>("certificate_requests_total");
        private static readonly Histogram<double> RequestDuration = Meter.CreateHistogram<double>("certificate_request_duration_ms");

        public CertificateController(IConfiguration configuration, ILogger<CertificateController> logger)
        {
            _configuration = configuration;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }
        [HttpGet]
        public ActionResult<byte[]> GetCertificateRawData()
        {
            var stopwatch = Stopwatch.StartNew();
            var activity = Activity.Current;
            var activitySource = DiagnosticConfig.ActivitySource.StartActivity("CertificateController.Get");
            long initialMemory = GC.GetTotalMemory(false);

            try
            {
                activitySource?.SetTag("http.method", "GET");
                activitySource?.SetTag("http.url", HttpContext.Request.Path);

                string certPath = _configuration["AppSettings:CertPfxPath"];
                string certPassword = _configuration["AppSettings:CertPfxPassword"];

                if (string.IsNullOrEmpty(certPath) || string.IsNullOrEmpty(certPassword))
                {
                    _logger.LogWarning("Certificado PFX ou senha não configurados corretamente.");
                    return BadRequest("Certificado PFX ou senha não configurados corretamente.");
                }

                X509Certificate2 cert;

                try
                {
                    cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.Exportable);
                }
                catch (Exception ex)
                {
                    Activity.Current?.SetTag("CertificateExcption", ex.Message);
                    Activity.Current?.SetTag("CertificateExMsg", "Erro ao carregar certificado PFX");
                    Activity.Current?.SetTag("CertificateExSource", ex.Source);
                    LogException(ex, stopwatch.Elapsed.TotalMilliseconds, activity, initialMemory);
                    return StatusCode(500, new { Message = "Erro ao carregar certificado PFX", Exception = ex.Message, StackTrace = ex.StackTrace });
                }

                byte[] rawData = cert.RawData;

                // Adicionar informações do certificado nos headers da resposta
                Response.Headers.Add("X-Certificate-Expiration", cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"));

                // Converter thumbprint para Base64 URL-safe
                string thumbprintBase64Url = Base64UrlEncode(cert.GetCertHash());

                // Adicionar thumbprint Base64 URL-safe nos headers da resposta
                Response.Headers.Add("X-Certificate-Thumbprint", thumbprintBase64Url);

                // Obter número serial do certificado como hexadecimal
                string serialNumberHex = cert.GetSerialNumberString();

                // Adicionar número serial hexadecimal nos headers da resposta
                Response.Headers.Add("X-Certificate-Serial-Number", serialNumberHex);

                Activity.Current?.SetTag("x.certificate.thumbprint", thumbprintBase64Url);
                Activity.Current?.SetTag("x.certificate.serial.number", serialNumberHex);
                Activity.Current?.SetTag("x.certificate.expiration", cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"));

                activitySource?.SetTag("http.status_code", 200);

                return Ok(rawData);
            }
            catch (Exception ex)
            {
                activitySource?.SetTag("error", true);
                activitySource?.SetTag("error.message", ex.Message);
                LogException(ex, stopwatch.Elapsed.TotalMilliseconds, activity, initialMemory);
                return StatusCode(500, new { Message = "Erro inesperado ao processar a solicitação" });
            }
            finally
            {
                stopwatch.Stop();
                long finalMemory = GC.GetTotalMemory(false);
                long memoryAllocated = finalMemory - initialMemory;

                RequestCounter.Add(1);
                RequestDuration.Record(stopwatch.Elapsed.TotalMilliseconds);

                DiagnosticConfig.RequestCounter.Add(1);
                DiagnosticConfig.RequestDuration.Record(stopwatch.Elapsed.TotalMilliseconds);

                _logger.LogInformation("Memory allocated during request: {MemoryAllocated} bytes", memoryAllocated);
                _logger.LogInformation("Request duration: {RequestDuration} ms", stopwatch.Elapsed.TotalMilliseconds);
                _logger.LogInformation(JsonSerializer.Serialize(memoryAllocated));
                AddRequestMetrics(activitySource, stopwatch.Elapsed.TotalMilliseconds);

                activitySource?.Stop();
                activity?.Stop();
            }
            
        }

        private string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                          .Replace('+', '-')
                          .Replace('/', '_')
                          .TrimEnd('=');
        }

        private void LogException(Exception ex, double requestDuration, Activity activity, long initialMemory)
        {
            long finalMemory = GC.GetTotalMemory(false);
            long memoryAllocated = finalMemory - initialMemory;

            var logDetails = new
            {
                Timestamp = DateTime.UtcNow,
                RequestPath = HttpContext.Request.Path,
                RequestMethod = HttpContext.Request.Method,
                ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
                Duration = requestDuration,
                MemoryAllocated = memoryAllocated,
                Exception = new CustomExceptionDetails(ex),
                EventId = activity?.Id,
                TraceId = activity?.TraceId.ToString(),
                SpanId = activity?.SpanId.ToString()
            };

            var memoryAllocatedMsg = new
            {
                Message = "Memory allocated during request",
                MemoryAllocated = memoryAllocated
            };

            AddRequestMetrics(activity, requestDuration);

            _logger.LogError(JsonSerializer.Serialize(logDetails));
            _logger.LogDebug(JsonSerializer.Serialize(memoryAllocatedMsg));
        }

        public static void AddRequestMetrics(Activity activity, double requestdurtaion)
        {
            var labels = new KeyValuePair<string, object?>(DiagnosticConfig.ServiceName, activity?.Id);

            DiagnosticConfig.RequestDuration.Record(requestdurtaion, labels);
            DiagnosticConfig.RequestCounter.Add(1, labels);
        }
    }
}
