using System;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SamlLibrary.Saml
{
    public class Response
    {
        private XmlDocument xmlDoc;
        private AccountSettings accountSettings;
        private Certificate certificate;

        public Response(AccountSettings accountSettings)
        {
            this.accountSettings = accountSettings;
            certificate = new Certificate();
            certificate.LoadCertificate(accountSettings.certificate);
        }

        public void LoadXml(string xml)
        {
            xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.XmlResolver = null;
            xmlDoc.LoadXml(xml);
        }

        public void LoadXmlFromBase64(string response)
        {
            System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
            LoadXml(enc.GetString(Convert.FromBase64String(response)));
        }

        public bool IsValid()
        {
            bool status = false;

            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            XmlNodeList nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

            SignedXml signedXml = new SignedXml(xmlDoc);
            foreach (XmlNode node in nodeList)
            {
                signedXml.LoadXml((XmlElement)node);
                status = signedXml.CheckSignature(certificate.Cert, true);
                if (!status)
                    return false;
            }
            return status;
        }

        public string GetNameID()
        {
            XmlNamespaceManager manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            XmlNode node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", manager);
            return node.InnerText;
        }
    }
}