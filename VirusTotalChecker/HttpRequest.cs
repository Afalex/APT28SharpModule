using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using VirusTotalChecker.Interfaces;
using VirusTotalChecker.Models.Input;

namespace VirusTotalChecker
{
  
    public class HttpRequest : IHttpRequests
    {
        #region POST
        public byte[] UploadFiles(string address,
            IEnumerable<UploadFile> files,
            NameValueCollection values, 
            Dictionary<string, string> additionalHeaders)
        {
            var request = WebRequest.Create(address);
            request.Method = "POST";
            var boundary = "---------------------------" + DateTime.Now.Ticks.ToString("x", NumberFormatInfo.InvariantInfo);
            request.ContentType = "multipart/form-data; boundary=" + boundary;
            boundary = "--" + boundary;

            foreach(var keyValuePair in additionalHeaders)
            {
                request.Headers.Add(keyValuePair.Key, keyValuePair.Value);
            }

            using (var requestStream = request.GetRequestStream())
            {
                // Write the values
                foreach (string name in values.Keys)
                {
                    var buffer = Encoding.ASCII.GetBytes(boundary + Environment.NewLine);
                    requestStream.Write(buffer, 0, buffer.Length);
                    buffer = Encoding.ASCII.GetBytes(string.Format("Content-Disposition: form-data; name=\"{0}\"{1}{1}", name, Environment.NewLine));
                    requestStream.Write(buffer, 0, buffer.Length);
                    buffer = Encoding.UTF8.GetBytes(values[name] + Environment.NewLine);
                    requestStream.Write(buffer, 0, buffer.Length);
                }

                // Write the files
                foreach (var file in files)
                {
                    var buffer = Encoding.ASCII.GetBytes(boundary + Environment.NewLine);
                    requestStream.Write(buffer, 0, buffer.Length);
                    buffer = Encoding.UTF8.GetBytes(string.Format("Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"{2}", file.Name, file.Filename, Environment.NewLine));
                    requestStream.Write(buffer, 0, buffer.Length);
                    buffer = Encoding.ASCII.GetBytes(string.Format("Content-Type: {0}{1}{1}", file.ContentType, Environment.NewLine));
                    requestStream.Write(buffer, 0, buffer.Length);
                    file.Stream.CopyTo(requestStream);
                    buffer = Encoding.ASCII.GetBytes(Environment.NewLine);
                    requestStream.Write(buffer, 0, buffer.Length);
                }

                var boundaryBuffer = Encoding.ASCII.GetBytes(boundary + "--");
                requestStream.Write(boundaryBuffer, 0, boundaryBuffer.Length);
            }

            using (var response = request.GetResponse())
            using (var responseStream = response.GetResponseStream())
            using (var stream = new MemoryStream())
            {
                responseStream.CopyTo(stream);
                return stream.ToArray();
            }
        }
        #endregion

        #region GET
        public string GET(string url, Dictionary<string, string> additionalHeaders)
        {
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(url);
            foreach (var keyValuePair in additionalHeaders)
                httpWebRequest.Headers.Add(keyValuePair.Key, keyValuePair.Value);
            HttpWebResponse response = (HttpWebResponse)httpWebRequest.GetResponse();
            Stream stream = response.GetResponseStream();
            return new StreamReader(stream).ReadToEnd();
        }
        #endregion
    }
}
