using System;

namespace VirusTotalChecker
{
    [Serializable]
    public class Data
    {
        [System.Text.Json.Serialization.JsonPropertyName("attributes")]
        public Attributes Attributes { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("id")]
        public string Id { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("type")]
        public string Type { get; set; }

    }
}
