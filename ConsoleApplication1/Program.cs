using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using mysign;
using SamlLibrary.Saml;

namespace ConsoleApplication1
{
    class Program
    {
        public static XmlDocument CreateSomeXml(string FileName)
        {
            var document = new XmlDocument();
            var node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");
            node.InnerText = "Example text to be signed.";
            document.AppendChild(node);

            using (var xmltw = new XmlTextWriter(FileName, new UTF8Encoding(false)))
            {
                document.WriteTo(xmltw);
                xmltw.Close();
            }
            return document;
        }

        public static bool IsValid(XmlDocument xmlDoc, X509Certificate2 certificate)
        {
            var status = false;

            var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            var nodeList = xmlDoc.SelectNodes("//ds:Signature", manager);

            var signedXml = new SignedXml(xmlDoc);
            foreach (XmlNode node in nodeList)
            {
                signedXml.LoadXml((XmlElement)node);
                status = signedXml.CheckSignature(certificate, true);
                if (!status)
                    return false;
            }
            return status;
        }

        public static void SignXmlFile(string FileName, string SignedFileName, X509Certificate2 cert)
        {
            if (null == FileName)
                throw new ArgumentNullException("FileName");
            if (null == SignedFileName)
                throw new ArgumentNullException("SignedFileName");

            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Format the document to ignore white spaces.
            doc.PreserveWhitespace = false;

            // Load the passed XML file using it's name.
            doc.Load(new XmlTextReader(FileName));

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document. 
            signedXml.SigningKey = cert.PrivateKey;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Create a new KeyInfo object.
            KeyInfo keyInfo = new KeyInfo();

            // Load the certificate into a KeyInfoX509Data object 
            // and add it to the KeyInfo object.
            keyInfo.AddClause(new KeyInfoX509Data(cert));

            // Add the KeyInfo object to the SignedXml object.
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));


            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            // Save the signed XML document to a file specified 
            // using the passed string. 
            using (XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false)))
            {
                doc.WriteTo(xmltw);
                xmltw.Close();
            }

        }

        // Verify the signature of an XML file against an asymetric  
        // algorithm and return the result. 
        public static Boolean VerifyXmlFile(String FileName, X509Certificate2 cert)
        {
            // Check the args. 
            if (null == FileName)
                throw new ArgumentNullException("FileName");

            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document. 
            xmlDocument.Load(FileName);

            // Create a new SignedXml object and pass it 
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new 
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result. 
            return signedXml.CheckSignature(cert, true);

        }
        public static void AppendSignatureToXMLDocument(XmlDocument xmlDoc, String referenceURI, X509Certificate2 certificate)
        {
            xmlDoc.PreserveWhitespace = true;
            var sig = new PrefixedSignedXML(xmlDoc) { SigningKey = certificate.PrivateKey };
            var key = new RSACryptoServiceProvider();
            // Add the key to the SignedXml xmlDocument.
            sig.SigningKey = key;

            // Create a reference to be signed.
            var reference = new Reference { Uri = ""};

            // Add an enveloped transformation to the reference.
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            sig.AddReference(reference);
            
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(certificate));
            sig.KeyInfo = keyInfo;

            // Compute the signature.
            sig.ComputeSignature();

            var signature = sig.GetXml("ds");

            var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(signature, true));

            //var node = xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", manager);

            ////var manager = new XmlNamespaceManager(xmlDoc.NameTable);
            ////manager.AddNamespace("saml", SignedXml.XmlDsigNamespaceUrl);
            ////var xmlResponse = xmlDoc.SelectSingleNode("saml:Assertion", manager);
            //node.AppendChild(signature);
        }

        public static X509Certificate2 GetCertificateBySubject(string certificateName)
        {
            X509Certificate2 cert = null;
            var store = new X509Store("My", StoreLocation.CurrentUser);

            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                // Find the certificate with the specified name. 
                foreach (var c in store.Certificates)
                    if (c.Subject == certificateName)
                    {
                        cert = c;
                        break;
                    }

                if (cert == null)
                    throw new CryptographicException("The certificate could not be found.");
            }
            finally
            {
                store.Close();
            }

            return cert;
        }
        static void Main(string[] args)
        {
            var valid = false;
            var certificate = GetCertificateBySubject("O=Internet Widgits Pty Ltd, S=BuenosAires, C=AR");
            SignXmlFile("Example.xml", "SignedExample.xml", certificate);
            valid = VerifyXmlFile("SignedExample.xml", certificate);

            var xmlDoc = CreateSomeXml("Example.xml");

            AppendSignatureToXMLDocument(xmlDoc, "a", certificate);
            valid = IsValid(xmlDoc, certificate);

        }
    }
}
