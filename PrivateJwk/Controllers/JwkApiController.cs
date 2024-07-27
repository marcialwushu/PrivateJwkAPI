﻿using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics.Metrics;
using System.Diagnostics;
using System.Text.Json;

namespace PrivateJwk.Controllers
{
    [ApiController]
    [Route("api/jwk")]
    public class JwkApiController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly DiagnosticConfig _diagnosticConfig;
        private readonly ILogger<JwkApiController> _logger;
        private static readonly Meter Meter = new Meter("PrivateJwk.Metrics", "1.0.0");
        private static readonly Counter<int> RequestCounter = Meter.CreateCounter<int>("jwk_requests_total");
        private static readonly Histogram<double> RequestDuration = Meter.CreateHistogram<double>("jwk_request_duration_ms");

        public JwkApiController(IConfiguration configuration, ILogger<JwkApiController> logger)
        {
            _configuration = configuration;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        [HttpGet]
        public ActionResult Get()
        {
            var stopwatch = Stopwatch.StartNew();
            var activity = Activity.Current;
            var activitySource = DiagnosticConfig.ActivitySource.StartActivity("JwkApiController.Get");


            try
            {
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
                    Activity.Current?.SetTag("JwkApi", ex.Message);
                    Activity.Current?.SetTag("JwkApi", "Erro ao carregar certificado PFX");
                    Activity.Current?.SetTag("JwkApi", ex.Source);
                    LogException(ex, stopwatch.Elapsed.TotalMilliseconds, activity);
                    return StatusCode(500, $"Erro ao carregar certificado PFX: {ex.Message}");
                }

                RSA rsa = cert.GetRSAPrivateKey() as RSA;
                if (rsa == null)
                {
                    var ex = new InvalidOperationException("Não foi possível obter a chave privada RSA do certificado.");
                    LogException(ex, stopwatch.Elapsed.TotalMilliseconds, activity);
                    return StatusCode(500, "Não foi possível obter a chave privada RSA do certificado.");
                }

                // Obter os parâmetros da chave privada RSA
                RSAParameters rsaParameters = rsa.ExportParameters(true);

                // Criação do JWK
                var jwk = new
                {
                    kty = "RSA",
                    use = "sig",
                    e = Base64UrlEncoder.Encode(rsaParameters.Exponent),
                    n = Base64UrlEncoder.Encode(rsaParameters.Modulus),
                    d = Base64UrlEncoder.Encode(rsaParameters.D),
                    p = Base64UrlEncoder.Encode(rsaParameters.P),
                    q = Base64UrlEncoder.Encode(rsaParameters.Q),
                    dp = Base64UrlEncoder.Encode(rsaParameters.DP),
                    dq = Base64UrlEncoder.Encode(rsaParameters.DQ),
                    qi = Base64UrlEncoder.Encode(rsaParameters.InverseQ),
                    x5tS256 = ComputeSha256Thumbprint(cert.RawData)
                };

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

                Activity.Current?.SetTag("JwkApi", thumbprintBase64Url);
                Activity.Current?.SetTag("JwkApi", serialNumberHex);
                Activity.Current?.SetTag("JwkApi", cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"));
                return Ok(rawData);
            }
            catch (Exception ex)
            {
                LogException(ex, stopwatch.Elapsed.TotalMilliseconds, activity);
                return StatusCode(500, "Erro inesperado ao processar a solicitação.");
            }
            finally
            {
                stopwatch.Stop();
                RequestCounter.Add(1);
                RequestDuration.Record(stopwatch.Elapsed.TotalMilliseconds);

                DiagnosticConfig.RequestCounter.Add(1);
                DiagnosticConfig.RequestDuration.Record(stopwatch.Elapsed.TotalMilliseconds);

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

        private string ComputeSha256Thumbprint(byte[] rawData)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] thumbprint = sha256.ComputeHash(rawData);
                return Base64UrlEncoder.Encode(thumbprint);
            }
        }

        private void LogException(Exception ex, double requestDuration, Activity activity)
        {
            var logDetails = new
            {
                Timestamp = DateTime.UtcNow,
                RequestPath = HttpContext.Request.Path,
                RequestMethod = HttpContext.Request.Method,
                ClientIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
                Duration = requestDuration,
                Exception = new CustomExceptionDetails(ex),
                EventId = activity?.Id,
                TraceId = activity?.TraceId.ToString(),
                SpanId = activity?.SpanId.ToString()
            };

            _logger.LogError(JsonSerializer.Serialize(logDetails));
        }

        public static void AddRequestMetrics(Activity activity, double requestdurtaion)
        {
            var labels = new KeyValuePair<string, object?> (DiagnosticConfig.ServiceName, activity?.Id);

            DiagnosticConfig.RequestDuration.Record(requestdurtaion, labels);
            DiagnosticConfig.RequestCounter.Add(1, labels);
        }
    }
}
