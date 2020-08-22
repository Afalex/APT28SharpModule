using System;
using System.Collections.Generic;
using System.Net.Http;
using System.IO;
using static VirusTotalChecker.HttpRequest;
using System.Collections.Specialized;
using System.Text;
using VirusTotalChecker.Models.Input;
using VirusTotalChecker.Models.Output;
using System.Text.Json;

namespace VirusTotalChecker
{
    class Program
    {
        const string VIRUSTOTAL_API_KEY = "424c20f594d7d9e90efe346d16e269b7f54fe422b3ecdd18b78d0caf4dc059bc";
        const string UPLOAD_URL = "https://www.virustotal.com/api/v3/files";// "https://www.virustotal.com/api/v3/files/upload_url";
        static HttpRequest requests = new HttpRequest();
        const string APi_HEADER_NAME = "x-apikey"; //header 'x-apikey: <your API key>'
        const string ANALYZE_API_URL = "https://www.virustotal.com/api/v3/analyses/";

        static void Main(string[] args)
        {
            Virustotal virustotal = new Virustotal();
            Dictionary<string, string> apiHeaders = new Dictionary<string, string>();
            string fileName = @"C:\Users\Afalex\Downloads\npp.7.8.9.Installer.exe";

            apiHeaders.Add(APi_HEADER_NAME, VIRUSTOTAL_API_KEY);
            Uploaded uploaded = SendFileToVirusTotal(UPLOAD_URL, fileName, apiHeaders);

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"File {fileName} uploaded, id: {uploaded.Data.Id}");

            string analyzeResponse = Analyze(uploaded.Data.Id, apiHeaders);
            Console.WriteLine("Analyze result:");
            Console.WriteLine(analyzeResponse);
            Console.ReadLine();
        }

      
        public class Virustotal
        {
            
            public static string Analyze(string id, Dictionary<string, string> additionalHeaders)
            {
                string json = requests.GET(ANALYZE_API_URL + id, additionalHeaders);
                return json;
            }

            public static Uploaded SendFileToVirusTotal(string uploadUrl, string fileName, Dictionary<string, string> additionalHeaders,
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
        }
    }
}
