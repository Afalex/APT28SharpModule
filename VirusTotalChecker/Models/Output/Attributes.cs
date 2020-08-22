using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VirusTotalChecker
{
    [Serializable]
    public class Attributes
    {
        [JsonPropertyName("date")]
        public int Date { get; set; }
        [JsonPropertyName("results")]
        public Dictionary<string, ResultUnit> Results { get; set; }
        [JsonPropertyName("status")]
        public string Status { get; set; }
    }
}
