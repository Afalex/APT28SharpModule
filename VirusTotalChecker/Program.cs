using System;
using System.Collections.Generic;
using System.Net.Http;
using static VirusTotalChecker.HttpRequest;
using VirusTotalChecker.Models.Output;
using static VirusTotalChecker.Program;

namespace VirusTotalChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            HttpRequest requests = new HttpRequest();
            VirusTotalConfiguration virusTotalConfiguration = new VirusTotalConfiguration();
            IVirusTotal virustotal = new VirusTotal(requests, virusTotalConfiguration);

          //  Dictionary<string, string> apiHeaders = new Dictionary<string, string>();
            string fileName = @"C:\Users\Afalex\Downloads\npp.7.8.9.Installer.exe";

            // apiHeaders.Add(APi_HEADER_NAME, VIRUSTOTAL_API_KEY);
            Uploaded uploaded = virustotal.SendFile(fileName);

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"File {fileName} uploaded, id: {uploaded.Data.Id}");

            string analyzeResponse = virustotal.Analyze(uploaded.Data.Id);
            Console.WriteLine("Analyze result:");
            Console.WriteLine(analyzeResponse);
            Console.ReadLine();
        }

    }
}
