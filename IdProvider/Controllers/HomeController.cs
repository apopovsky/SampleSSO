using System;
using System.Web.Mvc;
using SAML2;
using SAML2.Schema.Core;
using SAML2.Schema.Protocol;
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
            var assertion = new Assertion {Id = "ass_1", IssueInstant = DateTime.UtcNow, Version = "1.0"};
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
