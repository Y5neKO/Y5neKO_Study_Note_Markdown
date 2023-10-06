using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Web;
using HdhCms.AppCode;
using HdhCmsDll.HdhModel;
using HdhCmsCon;
using HdhCmsDll;

/// <summary>
/// Crawler 的摘要说明
/// </summary>
public class CrawlerHandler : Handler
{
    private string[] Sources;
    private Crawler[] Crawlers;
    public CrawlerHandler(HttpContext context) : base(context) { }

    public override void Process()
    {
        HdhAdminMain.AdminIsDemo();
        Sources = Request.Form.GetValues("source[]");
        if (Sources == null || Sources.Length == 0)
        {
            WriteJson(new
            {
                state = "参数错误：没有指定抓取源"
            });
            return;
        }
        Crawlers = Sources.Select(x => new Crawler(x, Server).Fetch()).ToArray();
        WriteJson(new
        {
            state = "SUCCESS",
            list = Crawlers.Select(x => new
            {
                state = x.State,
                source = x.SourceUrl,
                url = x.ServerUrl
            })
        });
    }
}

public class Crawler
{
    public string SourceUrl { get; set; }
    public string ServerUrl { get; set; }
    public string State { get; set; }

    private HttpServerUtility Server { get; set; }


    public Crawler(string sourceUrl, HttpServerUtility server)
    {
        this.SourceUrl = sourceUrl;
        this.Server = server;
    }

    public Crawler Fetch()
    {
        string Sql = "";
        var request = HttpWebRequest.Create(this.SourceUrl) as HttpWebRequest;
        using (var response = request.GetResponse() as HttpWebResponse)
        {
            if (response.StatusCode != HttpStatusCode.OK)
            {
                State = "Url returns " + response.StatusCode + ", " + response.StatusDescription;
                return this;
            }
            if (response.ContentType.IndexOf("image") == -1)
            {
                State = "Url is not an image";
                return this;
            }
            ServerUrl = PathFormatter.Format(Path.GetFileName(this.SourceUrl), Config.GetString("catcherPathFormat"));
            //ServerUrl=ServerUrl.Replace("image","images");

            #region 过滤非法上传
            var fileExtension = Path.GetExtension(ServerUrl);
            var allowExtension = new List<string>() { ".jpg", ".jpeg", ".gif", ".png", ".bmp" };
            if (!allowExtension.Contains(fileExtension.ToLower()))
            {
                State = "Url is not an image";
                return this;
            }
            else
            {

                var savePath = Server.MapPath(ServerUrl);
                if (!Directory.Exists(Path.GetDirectoryName(savePath)))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(savePath));
                }
                try
                {
                    var stream = response.GetResponseStream();
                    var reader = new BinaryReader(stream);
                    byte[] bytes;
                    using (var ms = new MemoryStream())
                    {
                        byte[] buffer = new byte[4096];
                        int count;
                        while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            ms.Write(buffer, 0, count);
                        }
                        bytes = ms.ToArray();
                    }
                    File.WriteAllBytes(savePath, bytes);
                    Sql = "insert into " + AllVar.SjkQz() + "DonforSctp(DonforWj,DonforYh) values('" + savePath.Remove(0, (savePath.IndexOf("upfiles") + 1)).Replace("\\", "/") + "','" + AllVar.WxUser + "')";
                    HdhCmsData.ExecuteCmd(Sql);
                    State = "SUCCESS";
                }
                catch (Exception e)
                {
                    State = "抓取错误：" + e.Message;
                }
            }
            #endregion

            return this;
        }
    }
}