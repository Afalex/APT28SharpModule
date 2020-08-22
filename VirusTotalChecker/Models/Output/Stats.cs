using System.Text.Json.Serialization;

namespace VirusTotalChecker
{
    public class Stats
    {
        [JsonPropertyName("confirmed-timeout")]
        public int ConfirmedTimeout { get; set; }
        [JsonPropertyName("failure")]
        public int Failure { get; set; }
        [JsonPropertyName("harmless")]
        public int Harmless { get; set; }
        [JsonPropertyName("suspicious")]
        public int Suspicious { get; set; }
        [JsonPropertyName("timeout")]
        public int Timeout { get; set; }
        [JsonPropertyName("type-unsupported")]
        public int TypeUnsupported { get; set; }
        [JsonPropertyName("undetected")]
        public int Undetected { get; set; }
    }
}
