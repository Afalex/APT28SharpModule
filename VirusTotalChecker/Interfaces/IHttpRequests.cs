using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using VirusTotalChecker.Models.Input;

namespace VirusTotalChecker.Interfaces
{
    public interface IHttpRequests
    {
        string GET(string url, Dictionary<string, string> additionalHeaders);
        byte[] UploadFiles(string address,
            IEnumerable<UploadFile> files,
            NameValueCollection values,
            Dictionary<string, string> additionalHeaders);
    }
}
