namespace PrivateJwk
{
    public class CustomExceptionDetails
    {
        public string Message { get; set; }
        public string StackTrace { get; set; }
        public string Source { get; set; }
        public string TargetSite { get; set; }

        public CustomExceptionDetails(Exception ex)
        {
            Message = ex.Message;
            StackTrace = ex.StackTrace;
            Source = ex.Source;
            TargetSite = ex.TargetSite?.ToString();
        }
    }
}
