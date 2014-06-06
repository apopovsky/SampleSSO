using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;

namespace IdProvider
{
    public static class Extensions
    {
        public static void AppendSignatureToXMLDocument(this XmlDocument xmlDoc, String referenceURI, X509Certificate2 certificate)
        {
            var sig = new SignedXml(xmlDoc) { SigningKey = certificate.PrivateKey };
            var key = new RSACryptoServiceProvider();
            // Add the key to the SignedXml xmlDocument.
            sig.SigningKey = key;

            // Create a reference to be signed.
            var reference = new Reference { Uri = "#" + referenceURI };

            // Add an enveloped transformation to the reference.
            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            sig.AddReference(reference);

            string path = Path.Combine(new DirectoryInfo(HttpContext.Current.Server.MapPath(@"~\")).Parent.FullName, "sign.crt");
            X509Certificate cert = X509Certificate.CreateFromCertFile(path);
            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            sig.KeyInfo = keyInfo;

            // Compute the signature.

            sig.ComputeSignature();

            var signature = sig.GetXml();
            var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("saml", SignedXml.XmlDsigNamespaceUrl);
            var xmlResponse = xmlDoc.SelectSingleNode("saml:Assertion", manager);
            xmlResponse.AppendChild(signature);
        }
    }

}