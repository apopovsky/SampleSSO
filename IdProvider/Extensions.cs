using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;
using mysign;

namespace mysign
{
    public class PrefixedSignedXML : SignedXml
    {
        public PrefixedSignedXML(XmlDocument document)
            : base(document)
        { }

        public PrefixedSignedXML(XmlElement element)
            : base(element)
        { }

        public PrefixedSignedXML()
        { }

        public void ComputeSignature(string prefix)
        {
            BuildDigestedReferences();
            var signingKey = SigningKey;
            if (signingKey == null)
            {
                throw new CryptographicException("Cryptography_Xml_LoadKeyFailed");
            }
            if (SignedInfo.SignatureMethod == null)
            {
                if (!(signingKey is DSA))
                {
                    if (!(signingKey is RSA))
                    {
                        throw new CryptographicException("Cryptography_Xml_CreatedKeyFailed");
                    }
                    if (SignedInfo.SignatureMethod == null)
                    {
                        SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
                    }
                }
                else
                {
                    SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
                }
            }
            var description = CryptoConfig.CreateFromName(SignedInfo.SignatureMethod) as SignatureDescription;
            if (description == null)
            {
                throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            var hash = description.CreateDigest();
            if (hash == null)
            {
                throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }
            GetC14NDigest(hash, prefix);
            m_signature.SignatureValue = description.CreateFormatter(signingKey).CreateSignature(hash);
        }

        public XmlElement GetXml(string prefix)
        {            
            var e = GetXml();
            SetPrefix(prefix, e);
            return e;
        }

        //Invocar por reflexión al método privado SignedXml.BuildDigestedReferences
        private void BuildDigestedReferences()
        {
            var t = typeof(SignedXml);
            var m = t.GetMethod("BuildDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance);
            m.Invoke(this, new object[] { });
        }

        private byte[] GetC14NDigest(HashAlgorithm hash, string prefix)
        {
            //string securityUrl = (this.m_containingDocument == null) ? null : this.m_containingDocument.BaseURI;
            //XmlResolver xmlResolver = new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
            var document = new XmlDocument();
            document.PreserveWhitespace = true;
            var e = SignedInfo.GetXml();
            document.AppendChild(document.ImportNode(e, true));
            //CanonicalXmlNodeList namespaces = (this.m_context == null) ? null : Utils.GetPropagatedAttributes(this.m_context);
            //Utils.AddNamespaces(document.DocumentElement, namespaces);

            var canonicalizationMethodObject = SignedInfo.CanonicalizationMethodObject;
            //canonicalizationMethodObject.Resolver = xmlResolver;
            //canonicalizationMethodObject.BaseURI = securityUrl;
            SetPrefix(prefix, document.DocumentElement); //establecemos el prefijo antes de se que calcule el hash (o de lo contrario la firma no será válida)
            canonicalizationMethodObject.LoadInput(document);
            return canonicalizationMethodObject.GetDigestedOutput(hash);
        }

        private void SetPrefix(string prefix, XmlNode node)
        {
            foreach (XmlNode n in node.ChildNodes)
                SetPrefix(prefix, n);
            node.Prefix = prefix;
        }
    }
}
namespace IdProvider
{
    public static class Extensions
    {
        public static void AppendSignatureToXMLDocument(this XmlDocument xmlDoc, String referenceURI, X509Certificate2 certificate)
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

            var path = Path.Combine(new DirectoryInfo(HttpContext.Current.Server.MapPath(@"~\")).Parent.FullName, "sign.crt");
            var cert = X509Certificate2.CreateFromCertFile(path);
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
    }

}