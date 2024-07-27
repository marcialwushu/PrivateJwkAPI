using System;
using System.Collections.Generic;
using System.Text.Json;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace PrivateJwk
{
    public class JsonConsoleExporter<T> : BaseExporter<T> where T : class
    {
        public override bool Equals(object? obj)
        {
            return base.Equals(obj);
        }

        public override ExportResult Export(in Batch<T> batch)
        {
            foreach (var item in batch)
            {
                Console.WriteLine(JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true }));
            }

            return ExportResult.Success;
        }

        
    }
}
