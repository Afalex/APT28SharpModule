using System;

namespace VirusTotalChecker
{
    [Serializable]
    public class Meta
    {
        [System.Text.Json.Serialization.JsonPropertyName("file_info")]
        public MetaFileInfo MetaFileInfo { get; set; }
    }
}
