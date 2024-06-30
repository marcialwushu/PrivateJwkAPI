using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;

namespace PrivateJwk.Controllers
{
    [ApiController]
    [Route("api/certificate")]
    public class CertificateController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public CertificateController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpGet]
        public ActionResult<byte[]> GetCertificateRawData()
        {
            string certPath = _configuration["AppSettings:CertPfxPath"];
            string certPassword = _configuration["AppSettings:CertPfxPassword"];

            if (string.IsNullOrEmpty(certPath) || string.IsNullOrEmpty(certPassword))
            {
                return BadRequest("Certificado PFX ou senha não configurados corretamente.");
            }

            X509Certificate2 cert;

            try
            {
                cert = new X509Certificate2(certPath, certPassword, X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Erro ao carregar certificado PFX: {ex.Message}");
            }

            byte[] rawData = cert.RawData;

            // Adicionar informações do certificado nos headers da resposta
            Response.Headers.Add("X-Certificate-Expiration", cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            Response.Headers.Add("X-Certificate-Thumbprint", cert.Thumbprint);
            Response.Headers.Add("X-Certificate-Serial-Number", cert.SerialNumber);

            return Ok(rawData);
        }
    }
}
