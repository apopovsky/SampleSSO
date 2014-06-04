using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using SAML2;
using SAML2.Protocol;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using KeyInfo = SAML2.Schema.XmlDSig.KeyInfo;
using Reference = SAML2.Schema.XmlDSig.Reference;

namespace ServiceProvider.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var requestXml = GetRequestXml();
            var model = new SamlRequestViewModel {SAMLRequest = requestXml.InnerXml, RelayState = Session.SessionID};
            return View(model);
        }

        private static XmlDocument GetRequestXml()
        {
            var request = new Saml20AuthnRequest();
            request.Id = "request_1";
            request.Request.Version = "1.0";
            var nameIdPolicy = new NameIdPolicy {Format = Saml20Constants.NameIdentifierFormats.Email};
            request.Request.NameIdPolicy = nameIdPolicy;
            request.Issuer = "http://localhost:15881/";

            var requestXml = request.GetXml();
            return requestXml;
        }

        [HttpPost]
        [ValidateInput(false)]
        public ActionResult Index(Response samlResponse, string relayState)
        {
            /*var handler = new Saml20SignonHandler();
            handler.ProcessRequest(System.Web.HttpContext.Current);*/
            ViewBag.Message = "Bienvenido " + User.Identity.Name;
            return View();
        }

        public ActionResult Test()
        {
            var requestXml = GetRequestXml();
            var sig = new SignedXml(requestXml);
            var key = new RSACryptoServiceProvider();

            // Add the key to the SignedXml xmlDocument.
            sig.SigningKey = key;

            // Create a reference to be signed.
            var reference = new System.Security.Cryptography.Xml.Reference {Uri = ""};

            // Add an enveloped transformation to the reference.
            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            sig.AddReference(reference);

            var path =Path.Combine(new DirectoryInfo(HttpContext.Server.MapPath(@"~\")).Parent.FullName, "sign.crt");
            var cert = X509Certificate.CreateFromCertFile(path);
            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            var keyInfo = new System.Security.Cryptography.Xml.KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            sig.KeyInfo = keyInfo;

            // Compute the signature.

            sig.ComputeSignature();
            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            return Content("Signature = " + sig.GetXml().OuterXml);
        }
    }

    public class SamlRequestViewModel
    {
        public string SAMLRequest { get; set; }
        public string RelayState { get; set; }
    }
}