using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace VirusTotalChecker.Models.Input
{
    public class UploadFile
    {
        public UploadFile()
        {
            ContentType = "application/octet-stream";
        }
        public string Name { get; set; }
        public string Filename { get; set; }
        public string ContentType { get; set; }
        public Stream Stream { get; set; }
    }

}
