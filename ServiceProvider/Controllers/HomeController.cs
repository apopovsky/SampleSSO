using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using ServiceProvider.Controllers.Saml;

namespace ServiceProvider.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var requestXml = GetRequestXml();
            var model = new SamlRequestViewModel {SAMLRequest = requestXml, RelayState = Session.SessionID};
            return View(model);
        }

        private static string GetRequestXml()
        {
            var request = new AuthRequest();
            
            var requestXml = request.GetRequest(AuthRequest.AuthRequestFormat.Xml);
            return requestXml;
        }


        [HttpPost]
        [ValidateInput(false)]
        public ActionResult Index(string SAMLResponse, string relayState)
        {
            var sResponse = new Response();
            sResponse.LoadXml(SAMLResponse);
            if (sResponse.IsValid())
            {
                ViewBag.Message = "Bienvenido " + sResponse.GetNameID();
            }
            else
            {
                ViewBag.Message = ("Failed");
            }

            return View();
        }
    }

    public class SamlRequestViewModel
    {
        public string SAMLRequest { get; set; }
        public string RelayState { get; set; }
    }


    namespace Saml
    {
        public class Certificate
        {
            public X509Certificate2 cert;

            public void LoadCertificate(string certificate)
            {
                cert = new X509Certificate2();
                cert.Import(StringToByteArray(certificate));
            }

            public void LoadCertificate(byte[] certificate)
            {
                cert = new X509Certificate2();
                cert.Import(certificate);
            }

            private byte[] StringToByteArray(string st)
            {
                var bytes = new byte[st.Length];
                for (var i = 0; i < st.Length; i++)
                {
                    bytes[i] = (byte)st[i];
                }
                return bytes;
            }
        }

        public class Response
        {
            private XmlDocument xmlDoc;
            private readonly Certificate certificate;

            public Response()
            {                
            }

            public void LoadXml(string xml)
            {
                xmlDoc = new XmlDocument {PreserveWhitespace = true, XmlResolver = null};
                xmlDoc.LoadXml(xml);
            }

            public void LoadXmlFromBase64(string response)
            {
                var enc = new ASCIIEncoding();
                LoadXml(enc.GetString(Convert.FromBase64String(response)));
            }

            public bool IsValid()
            {
                var status = false;

                var manager = new XmlNamespaceManager(xmlDoc.NameTable);
                manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                var nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

                var signedXml = new SignedXml(xmlDoc);
                foreach (XmlNode node in nodeList)
                {
                   // signedXml.LoadXml((XmlElement)node);
                    var path = Path.Combine(new DirectoryInfo(HttpContext.Current.Server.MapPath(@"~\")).Parent.FullName, "sign.crt");
                    var cert = new X509Certificate2(path);

                    status = signedXml.CheckSignature(cert, true);
                    if (!status)
                        return false;
                }
                return status;
            }

            public string GetNameID()
            {
                var manager = new XmlNamespaceManager(xmlDoc.NameTable);
                manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

                var node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", manager);
                return node.InnerText;
            }
        }

        public class AuthRequest
        {
            public string id;
            private readonly string issueInstant;
            private string issuer = "http://localhost";

            public enum AuthRequestFormat
            {
                Base64 = 1,
                Xml
            }

            public AuthRequest()
            {
                id = "_" + Guid.NewGuid();
                issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
            }

            public string GetRequest(AuthRequestFormat format)
            {
                using (var sw = new StringWriter())
                {
                    var xws = new XmlWriterSettings {OmitXmlDeclaration = true};

                    using (var xw = XmlWriter.Create(sw, xws))
                    {
                        xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("ID", id);
                        xw.WriteAttributeString("Version", "2.0");
                        xw.WriteAttributeString("IssueInstant", issueInstant);
                        xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                        xw.WriteAttributeString("AssertionConsumerServiceURL", "http://localhost");

                        xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
                        xw.WriteString(issuer);
                        xw.WriteEndElement();

                        xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
                        xw.WriteAttributeString("AllowCreate", "true");
                        xw.WriteEndElement();

                        xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
                        xw.WriteAttributeString("Comparison", "exact");
                        xw.WriteEndElement();

                        xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
                        xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
                        xw.WriteEndElement();

                        xw.WriteEndElement();
                    }

                    if (format == AuthRequestFormat.Base64)
                    {
                        var toEncodeAsBytes = ASCIIEncoding.ASCII.GetBytes(sw.ToString());
                        return Convert.ToBase64String(toEncodeAsBytes);
                    }

                    return sw.ToString();
                }
            }
        }
    }
}