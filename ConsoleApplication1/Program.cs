using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using mysign;
using SamlLibrary.Saml;

namespace ConsoleApplication1
{
    class Program
    {
        static string certPath = Path.Combine(Directory.GetCurrentDirectory(),  "sign.crt");

        public static bool IsValid(XmlDocument xmlDoc, Certificate certificate)
        {
            var status = false;

            var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            var nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

            var signedXml = new SignedXml(xmlDoc);
            foreach (XmlNode node in nodeList)
            {
                signedXml.LoadXml((XmlElement)node);
                status = signedXml.CheckSignature(certificate.Cert, true);
                if (!status)
                    return false;
            }
            return status;
        }

        public static void AppendSignatureToXMLDocument(XmlDocument xmlDoc, String referenceURI, X509Certificate2 certificate)
        {
            var sig = new PrefixedSignedXML(xmlDoc) { SigningKey = certificate.PrivateKey };
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

            
            var cert = X509Certificate2.CreateFromCertFile(certPath);
            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            sig.KeyInfo = keyInfo;

            // Compute the signature.

            sig.ComputeSignature();

            var signature = sig.GetXml("ds");

            var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            var node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", manager);

            //var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            //manager.AddNamespace("saml", SignedXml.XmlDsigNamespaceUrl);
            //var xmlResponse = xmlDoc.SelectSingleNode("saml:Assertion", manager);
            node.AppendChild(signature);
        }
        static void Main(string[] args)
        {
            var valid = false;
            var xmlDoc = new XmlDocument();
            AppendSignatureToXMLDocument(xmlDoc, "a", null);
            valid = IsValid(xmlDoc, null);

        }
    }
}
