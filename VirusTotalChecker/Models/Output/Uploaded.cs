using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace VirusTotalChecker.Models.Output
{
    public class Uploaded
    {
        [JsonPropertyName("data")]
        public Data Data { get; set; }
    }
    /// <summary>
    /// Uploaded file information
    /// </summary>
    public class Data
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }
        [JsonPropertyName("type")]
        public string Type { get; set; }
    }
}
