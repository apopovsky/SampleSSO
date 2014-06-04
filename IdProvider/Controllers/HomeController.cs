using System;
using System.Web.Mvc;
using SAML2;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Schema.XmlDSig;
using SAML2.Utils;

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
                        new CanonicalizationMethod {Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"},
                    SignatureMethod = new SignatureMethod
                    {
                        Algorithm = "http: //www.w3.org/2000/09/xmldsig#rsa-sha1"
                    },
                    Reference = new[]
                    {
                        new Reference
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
                Signature = signature
            };
            response.Items = new object[] {assertion};
            response.InResponseTo = "message_1";

            var nameId = new NameId {Value = "123"};
            response.Issuer = nameId;

            var model = new SAMLResponseViewModel { SAMLResponse = Serialization.SerializeToXmlString(response), RelayState = relayState };
            return View(model);
        }

    }

    public class SAMLResponseViewModel
    {
        public string SAMLResponse { get; set; }
        public string RelayState { get; set; }
    }
}
