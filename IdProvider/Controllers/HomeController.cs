using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;
using System.Xml;
using SAML2;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Schema.XmlDSig;
using SAML2.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Xml;
using System.Security.Cryptography.Xml;
using Signature = SAML2.Schema.XmlDSig.Signature;
using SignedInfo = SAML2.Schema.XmlDSig.SignedInfo;
using Reference = System.Security.Cryptography.Xml.Reference;

namespace IdProvider.Controllers
{
    [HandleError(View = "Error")]
    public class HomeController : Controller
    {
        //
        // GET: /Home/
        [ValidateInput(false)]
        public ActionResult Index(Saml20AuthnRequest samlRequest, string relayState)
        {
            var response = new Response();
            var status = new Status();
            response.Status = status;
            status.StatusCode = new StatusCode
            {
                Value = Saml20Constants.StatusCodes.Success
            };

            var issuer = new NameId
            {
                Format = Saml20Constants.NameIdentifierFormats.Transient,
                Value = "http://localhost:35513/"
            };

            var signature = new Signature
            {
                SignedInfo = new SignedInfo
                {
                    CanonicalizationMethod =
                        new CanonicalizationMethod { Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#" },
                    SignatureMethod = new SignatureMethod
                    {
                        Algorithm = "http: //www.w3.org/2000/09/xmldsig#rsa-sha1"
                    },
                    Reference = new[]
                    {
                        new SAML2.Schema.XmlDSig.Reference
                        {
                            DigestMethod = new DigestMethod
                            {
                                Algorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
                            },
                            //Transforms = new []{new Transform{Algorithm = }}
                        }
                    }
                }
            };

            var assertion = new Assertion
            {
                Id = "ass_1",
                IssueInstant = DateTime.UtcNow,
                Version = "1.0",
                Issuer = issuer,
                Signature = signature,
                Subject = new Subject
                {
                    Items =
                        new object[] { new NameId { Format = Saml20Constants.NameIdentifierFormats.Email, Value = "pepe@gmail.com" } }
                }
            };
            response.Items = new object[] { assertion };
            response.InResponseTo = "message_1";

            var nameId = new NameId { Value = "123" };
            response.Issuer = nameId;

            var path = Path.Combine(new DirectoryInfo(HttpContext.Server.MapPath(@"~\")).Parent.FullName, "sign.crt");
            var cert = new X509Certificate2(path);

            var r = Serialization.Serialize(response);
            r.AppendSignatureToXMLDocument("ass_1", cert);
            var model = new SAMLResponseViewModel { SAMLResponse = r.OuterXml, RelayState = relayState };
            return View(model);
        }

        public static void AppendSignatureToXMLDocument(ref XmlDocument XMLSerializedSAMLResponse, String ReferenceURI, X509Certificate2 SigningCert)
        {
            var signedXML = new SignedXml(XMLSerializedSAMLResponse);

            signedXML.SigningKey = SigningCert.PrivateKey;
            signedXML.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var reference = new Reference();
            reference.Uri = "#" + ReferenceURI;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXML.AddReference(reference);
            signedXML.ComputeSignature();

            var signature = signedXML.GetXml();

            var xeResponse = XMLSerializedSAMLResponse.DocumentElement;

            xeResponse.AppendChild(signature);
        }
    }

    public class SAMLResponseViewModel
    {
        public string SAMLResponse { get; set; }
        public string RelayState { get; set; }
    }
}
