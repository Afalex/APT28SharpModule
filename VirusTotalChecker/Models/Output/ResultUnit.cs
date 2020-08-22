using System;
using System.Text.Json.Serialization;

namespace VirusTotalChecker
{
    [Serializable]
    public class ResultUnit
    {
        [JsonPropertyName("category")]
        public string Category { get; set; }
        [JsonPropertyName("engine_name")]
        public string EngineName { get; set; }
        [JsonPropertyName("engine_update")]
        public string EngineUpdate { get; set; }
        [JsonPropertyName("engine_version")]
        public string EngineVersion { get; set; }
        [JsonPropertyName("method")]
        public string Method { get; set; }
        [JsonPropertyName("result")]
        public string Result { get; set; }
    }
}
