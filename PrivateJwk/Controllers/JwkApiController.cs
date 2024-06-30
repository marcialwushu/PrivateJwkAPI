﻿using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace PrivateJwk.Controllers
{
    [ApiController]
    [Route("api/jwk")]
    public class JwkApiController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public JwkApiController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        public ActionResult Get()
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

            RSA rsa = cert.GetRSAPrivateKey() as RSA;
            if (rsa == null)
            {
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

            // Adicionando informações do certificado ao header da resposta
            Response.Headers.Add("X-Certificate-Expiration", cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            Response.Headers.Add("X-Certificate-Thumbprint", cert.Thumbprint);
            Response.Headers.Add("X-Certificate-Serial-Number", cert.SerialNumber);

            return Ok(jwk);
        }

        private string ComputeSha256Thumbprint(byte[] rawData)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] thumbprint = sha256.ComputeHash(rawData);
                return Base64UrlEncoder.Encode(thumbprint);
            }
        }
    }
}