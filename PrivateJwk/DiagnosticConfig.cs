using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace PrivateJwk
{
    public class DiagnosticConfig
    {
        public const string ServiceName = "PrivateJwk";
        public static Meter Meter = new Meter(ServiceName, "1.0.0");
        public static Histogram<double> RequestDuration = Meter.CreateHistogram<double>("jwk_request_duration_ms");
        public static Counter<int> RequestCounter = Meter.CreateCounter<int>("jwk_requests_total");
        public static ActivitySource ActivitySource = new ActivitySource(ServiceName);
    }
}
