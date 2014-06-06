using System.Security.Cryptography.X509Certificates;

namespace SamlLibrary.Saml
{
    public class Certificate
    {
        public X509Certificate2 Cert;

        public void LoadCertificate(string certificate)
        {
            Cert = new X509Certificate2();
            Cert.Import(StringToByteArray(certificate));
        }

        public void LoadCertificate(byte[] certificate)
        {
            Cert = new X509Certificate2();
            Cert.Import(certificate);
        }

        private byte[] StringToByteArray(string st)
        {
            byte[] bytes = new byte[st.Length];
            for (int i = 0; i < st.Length; i++)
            {
                bytes[i] = (byte)st[i];
            }
            return bytes;
        }
    }
}