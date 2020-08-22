namespace VirusTotalChecker.Models.Output
{
    public delegate string AnalyzeDone(string result);
    public static class UploadedExtenstions
    {
        public static string Analyze(this Uploaded uploaded, IVirusTotal virustotal)
        {
            return virustotal.Analyze(uploaded.Data.Id);
        }
    }
    public interface IObserver
    {
        void Update(string ob);
    }
    public interface IObservable
    {
        void Subscribe(IObserver o);
        void UnSubscribe(IObserver o);
        void Notify(string result);
    }
}
