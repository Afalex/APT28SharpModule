namespace VirusTotalChecker
{
    public class VirusTotalConfiguration
    {
        public string VIRUSTOTAL_API_KEY { get; set; } = "424c20f594d7d9e90efe346d16e269b7f54fe422b3ecdd18b78d0caf4dc059bc";
        public string UPLOAD_URL { get; set; } = "https://www.virustotal.com/api/v3/files";
        public string APi_HEADER_NAME { get; set; } = "x-apikey"; //header 'x-apikey: <your API key>'
        public string ANALYZE_API_URL { get; set; } = "https://www.virustotal.com/api/v3/analyses/";
    }
}
