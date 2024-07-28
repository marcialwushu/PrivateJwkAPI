using System.Diagnostics;

namespace PrivateJwk.Extensions
{
    public static class ActivityExtensions
    {
        public static Activity StartActivitywithTags(this ActivitySource source, string name, List<KeyValuePair<string, object>> tags)
        {
            return source.StartActivity(name, 
                ActivityKind.Internal, 
                Activity.Current?.Context ?? new ActivityContext(),
                tags);
        }
    }
}
