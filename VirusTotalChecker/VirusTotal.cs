using System.Collections.Generic;
using System.IO;
using System.Collections.Specialized;
using System.Text;
using VirusTotalChecker.Models.Input;
using VirusTotalChecker.Models.Output;
using System.Text.Json;
using VirusTotalChecker.Interfaces;

namespace VirusTotalChecker
{
    public interface IVirusTotal
    {
        string Analyze(string id);
        Uploaded SendFile(string fileName);
    }
    public class VirusTotal : IVirusTotal
    {
        IHttpRequests requests;
        VirusTotalConfiguration configuration;
        Dictionary<string, string> apiHeaders = new Dictionary<string, string>();
        public VirusTotal(IHttpRequests requests, VirusTotalConfiguration configuration)
        {
            this.requests = requests;
            this.configuration = configuration;

            apiHeaders.Add(configuration.APi_HEADER_NAME, configuration.VIRUSTOTAL_API_KEY);
        }
      
        #region IVirusTotal
        string IVirusTotal.Analyze(string id)
        {
            return Analyze(id, apiHeaders);
        }
        Uploaded IVirusTotal.SendFile(string fileName)
        {
            return SendFileToVirusTotal(configuration.UPLOAD_URL, fileName, apiHeaders);
        }
        #endregion
        #region Private
        private string Analyze(string id, Dictionary<string, string> additionalHeaders)
        {
            string json = requests.GET(configuration.ANALYZE_API_URL + id, additionalHeaders);
            return json;
        }
        private Uploaded SendFileToVirusTotal(string uploadUrl, string fileName, Dictionary<string, string> additionalHeaders,
            NameValueCollection postRequestForm = null)
        {
            using (var stream = File.Open(fileName, FileMode.Open))
            {
                var files = new[]
                {
        new UploadFile
        {
            Name = "file",
            Filename = Path.GetFileName(fileName),
            ContentType = "text/plain",
            Stream = stream
        }
    };
                byte[] responseBytes = requests.UploadFiles(uploadUrl, files, postRequestForm ?? new NameValueCollection(), additionalHeaders);
                string json = Encoding.UTF8.GetString(responseBytes);
                Uploaded uploadedInformation = JsonSerializer.Deserialize<Uploaded>(json);
                return uploadedInformation;
            }
        }
        #endregion
    }
}
