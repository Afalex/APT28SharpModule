using System;

namespace VirusTotalChecker
{
    [Serializable]
    public class MetaFileInfo
    {
        [System.Text.Json.Serialization.JsonPropertyName("md5")]
        public string Md5 { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("name")]
        public string Name { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("sha1")]
        public string Sha1 { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("sha256")]
        public string Sha256 { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("size")]
        public double Size { get; set; }
    }
}
