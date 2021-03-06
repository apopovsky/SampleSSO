﻿using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;
using System.Xml;
using SAML2;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using System.Security.Cryptography.Xml;
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

            var assertion = new Assertion
            {
                Id = "ass_1",
                IssueInstant = DateTime.UtcNow,
                Version = "1.0",
                Issuer = issuer,
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
    }

    public class SAMLResponseViewModel
    {
        public string SAMLResponse { get; set; }
        public string RelayState { get; set; }
    }
}
