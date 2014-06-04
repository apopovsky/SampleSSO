using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using SAML2;
using SAML2.Protocol;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
using SAML2.Utils;

namespace ServiceProvider.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var request = new Saml20AuthnRequest();
            request.Id = "request_1";
            request.Request.Version = "1.0";
            var nameIdPolicy = new NameIdPolicy {Format = Saml20Constants.NameIdentifierFormats.Email};
            request.Request.NameIdPolicy = nameIdPolicy;
            request.Issuer = "http://localhost:15881/";

            var model = new SamlRequestViewModel { SAMLRequest = request.GetXml().InnerXml, RelayState = Session.SessionID };
            return View(model);
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

    }

    public class SamlRequestViewModel
    {
        public string SAMLRequest { get; set; }
        public string RelayState { get; set; }
    }
}
