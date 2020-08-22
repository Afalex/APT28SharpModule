using System;

namespace VirusTotalChecker
{
    [Serializable]
    public class Result
    {
        [System.Text.Json.Serialization.JsonPropertyName("data")]
        public Data Data { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("meta")]
        public Meta Meta { get; set; }
    }
}
