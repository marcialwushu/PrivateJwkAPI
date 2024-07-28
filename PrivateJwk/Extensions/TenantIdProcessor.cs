using System.Diagnostics;

namespace PrivateJwk.Extensions
{
    public class TenantIdProcessor
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public TenantIdProcessor(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public void OnStart(Activity data)
        {
            var tenantId = _httpContextAccessor.HttpContext?.Request.Headers["x-tenant-id"];
            if (!tenantId.HasValue)
                return;

            data.SetTag("tenant.id", tenantId.Value.First());
        }
    }
}
