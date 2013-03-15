using System.Drawing;
using System.Text.RegularExpressions;

namespace BtcAddress.Barcode {
    public class QR {

        /// <summary>
        /// Encodes a QR code, making the best choice based on string length
        /// (apparently not provided by QR lib?)
        /// </summary>
        public static Bitmap EncodeQRCode(string what) {
            if (string.IsNullOrEmpty(what)) return null;

            // Determine if we can use alphanumeric encoding (e.g. public key hex)
            var r = new Regex("^[0-9A-F]{63,154}$");
            var isAlphanumeric = r.IsMatch(what);

            var qr = new QRCodeEncoder();
            if (isAlphanumeric)
            {
                qr.QRCodeEncodeMode = QRCodeEncoder.ENCODE_MODE.ALPHA_NUMERIC;
                if (what.Length <= 154)
                {
                    if (what.Length > 67)
                    {
                        // 5L is good to 154 alphanumeric characters
                        qr.QRCodeVersion = 5;
                        qr.QRCodeErrorCorrect = QRCodeEncoder.ERROR_CORRECTION.L;
                    }
                    else
                    {
                        // 4Q is good to 67 alphanumeric characters
                        qr.QRCodeVersion = 4;
                        qr.QRCodeErrorCorrect = QRCodeEncoder.ERROR_CORRECTION.Q;
                    }
                }
                else
                {
                    return null;
                }
            }
            else {
                if (what.Length > 84) {
                    // We don't intend to encode any alphanumeric strings longer than confirmation codes at 75 characters
                    return null;
                } else if (what.Length > 62) {
                    // 5M is good to 84 characters
                    qr.QRCodeVersion = 5;
                    qr.QRCodeErrorCorrect = QRCodeEncoder.ERROR_CORRECTION.M;
                } else if (what.Length > 34) {
                    // 4M is good to 62 characters
                    qr.QRCodeVersion = 4;
                    qr.QRCodeErrorCorrect = QRCodeEncoder.ERROR_CORRECTION.M;
                } else if (what.Length > 32) {
                    // 4H is good to 34 characters
                    qr.QRCodeVersion = 4;
                    qr.QRCodeErrorCorrect = QRCodeEncoder.ERROR_CORRECTION.H;
                } else {
                    // 3Q is good to 32 characters
                    qr.QRCodeVersion = 3;
                    qr.QRCodeErrorCorrect = QRCodeEncoder.ERROR_CORRECTION.Q;
                }
            }

            return qr.Encode(what);
        }

    }
}
