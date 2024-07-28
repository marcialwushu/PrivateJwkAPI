
namespace PrivateJwk
{
    internal class DiagnosticSourceInstrumentation
    {
        private IServiceProvider activitySource;

        public DiagnosticSourceInstrumentation(IServiceProvider activitySource)
        {
            this.activitySource = activitySource;
        }
    }
}