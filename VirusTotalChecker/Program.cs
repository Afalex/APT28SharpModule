using System;
using System.Collections.Generic;
using System.Net.Http;
using static VirusTotalChecker.HttpRequest;
using VirusTotalChecker.Models.Output;
using static VirusTotalChecker.Program;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Tasks;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Linq;

namespace VirusTotalChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            HttpRequest requests = new HttpRequest();
            VirusTotalConfiguration virusTotalConfiguration = new VirusTotalConfiguration();
            IVirusTotal virustotal = new VirusTotal(requests, virusTotalConfiguration);
            ResultDataContext resultDataContext = new ResultDataContext();

            string fileName = args.First();

            Uploaded uploaded = virustotal.SendFile(fileName);

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine($"File {fileName} uploaded, id: {uploaded.Data.Id}");
            Console.WriteLine("Analyze started..please wait");
            string analyzeResponse = virustotal.Analyze(uploaded.Data.Id);
            Result result = JsonSerializer.Deserialize<Result>(analyzeResponse);

            if (result.Data.Attributes.Status == "queued")
            {
                Task<(Result,string)> task = new Task<(Result, string)>(
                    () =>
                {
                    Result result = null;
                    do
                    {
                        string analyzeResponse = virustotal.Analyze(uploaded.Data.Id);
                        result = JsonSerializer.Deserialize<Result>(analyzeResponse);
                    }
                    while (result.Data.Attributes.Status == "queued");
                    return (result, analyzeResponse);
                });
                task.Start();
                task.Wait();
                (result, analyzeResponse) = task.Result;
            }
            resultDataContext.Add(new AnalyzedFile() { FilePath = fileName, Id = result.Data.Id, Result = result, Status = result.Data.Attributes.Status });

            Console.WriteLine("Analyze result:");
            Console.WriteLine(analyzeResponse);
            Console.ReadLine();
        }

    }
    public interface IAnalyzeResultContext
    {
        AnalyzedFile Add(AnalyzedFile file);
        List<AnalyzedFile> List();
    }

    public class ResultDataContext : IAnalyzeResultContext
    {
        const string ResultFolder = "AnalyzeResults";
        BinaryFormatter formatter = new BinaryFormatter();

        public AnalyzedFile Add(AnalyzedFile file)
        {
            string fileName = $"{file.Id}.dat";
            string path = Path.Combine(ResultFolder, fileName);

            if (!Directory.Exists(ResultFolder))
                Directory.CreateDirectory(ResultFolder);

            using (FileStream fs = new FileStream($"{file.Id}.dat", FileMode.OpenOrCreate))
                formatter.Serialize(fs, file);

            return file;
        }

        public List<AnalyzedFile> List()
        {
            List<AnalyzedFile> analyzedFiles = new List<AnalyzedFile>();
            if (Directory.Exists(ResultFolder))
            {
                string[] files = Directory.GetFiles(ResultFolder);
                foreach (string file in files)
                {
                    using (FileStream fs = new FileStream(file, FileMode.OpenOrCreate))
                    {
                        AnalyzedFile newFile = (AnalyzedFile)formatter.Deserialize(fs);
                        analyzedFiles.Add(newFile);
                    }
                }
            }
            Directory.CreateDirectory(ResultFolder);
            return analyzedFiles;
        }
    }
    [Serializable]
    public class AnalyzedFile
    {
        public string FilePath { get; set; }
        public string Id { get; set; }
        public Result Result { get; set; }
        public string Status { get; set; }
    }
}
