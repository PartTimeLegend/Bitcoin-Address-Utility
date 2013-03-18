// Copyright 2012 Mike Caldwell (Casascius)
// This file is part of Bitcoin Address Utility.

// Bitcoin Address Utility is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Bitcoin Address Utility is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Bitcoin Address Utility.  If not, see http://www.gnu.org/licenses/.


using System;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using BtcAddress.CryptSharp;
using BtcAddress.Properties;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Casascius.Bitcoin;

namespace BtcAddress.Forms {
    public partial class Bip38ConfValidator : Form {
        public Bip38ConfValidator() {
            InitializeComponent();
        }

        private void btnConfirm_Click(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            lblAddressHeader.Visible = false;
            lblAddressItself.Visible = false;
            lblResult.Visible = false;
            

            // check for null entry
            if (string.IsNullOrWhiteSpace(txtPassphrase.Text)) {
                MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_Passphrase_is_required_, Resources.Bip38ConfValidator_btnConfirm_Click_Passphrase_required, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            if (string.IsNullOrWhiteSpace(txtConfCode.Text)) {
                MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_Confirmation_code_is_required_, Resources.Bip38ConfValidator_btnConfirm_Click_Confirmation_code_required, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            // Parse confirmation code.
            var confbytes = Util.Base58CheckToByteArray(txtConfCode.Text.Trim());
            if (confbytes == null) {
                // is it even close?
                if (txtConfCode.Text.StartsWith("cfrm38")) {
                    MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_is_not_a_valid_confirmation_code___It_has_the_right_prefix__but_doesn_t_contain_valid_confirmation_data___Possible_typo_or_incomplete_, 
                        Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_confirmation_code, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return;
                }

                MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_is_not_a_valid_confirmation_code_, Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_confirmation_code, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            if (confbytes.Length != 51 || confbytes[0] != 100 || confbytes[1] != 59 || confbytes[2] != 246 ||
                confbytes[3] != 168 || confbytes[4] != 154 || confbytes[18] < 2 || confbytes[18] > 3) {

                // Unrecognized Base58 object.  Do we know what this is?  Tell the user.
                var result = StringInterpreter.Interpret(txtConfCode.Text.Trim());
                if (result != null) {

                    // did we actually get an encrypted private key?  if so, just try to decrypt it.
                    if (result is PassphraseKeyPair) {
                        var ppkp = result as PassphraseKeyPair;
                        if (ppkp.DecryptWithPassphrase(txtPassphrase.Text)) {
                            var addressBase58 = ppkp.GetAddress().AddressBase58;
                            if (addressBase58 != null)
                                confirmIsValid(addressBase58);
                            MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_What_you_provided_contains_a_private_key__not_just_a_confirmation__Confirmation_is_successful__and_with_this_correct_passphrase__you_are_also_able_to_spend_the_funds_from_the_address_, Resources.Bip38ConfValidator_btnConfirm_Click_This_is_actually_a_private_key,
                                MessageBoxButtons.OK, MessageBoxIcon.Information);
                            return;
                        } else {
                            MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_is_not_a_valid_confirmation_code___It_looks_like_an_encrypted_private_key___Decryption_was_attempted_but_the_passphrase_couldn_t_decrypt_it, Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_confirmation_code, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                            return;
                        }
                    }

                    var objectKind = result.GetType().Name;
                    objectKind = objectKind == "AddressBase" ? "an Address" : "a " + objectKind;

                    MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_is_not_a_valid_confirmation_code___Instead__it_looks_like_ + objectKind +
                      Resources.Bip38ConfValidator_btnConfirm_Click____Perhaps_you_entered_the_wrong_thing___Confirmation_codes_ +
                    Resources.Bip38ConfValidator_btnConfirm_Click_start_with__cfrm__, Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_confirmation_code, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return;
                }

                MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_is_not_a_valid_confirmation_code_, Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_confirmation_code, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
                
            }

            // extract ownersalt and get an intermediate
            var ownersalt = new byte[8];
            Array.Copy(confbytes, 10, ownersalt, 0, 8);

            var includeHashStep = confbytes.Length > 5 && (confbytes[5] & 0x04) == 0x04;
            var intermediate = new Bip38Intermediate(txtPassphrase.Text, ownersalt, includeHashStep);

            // derive the 64 bytes we need
            // get ECPoint from passpoint            
            if (intermediate.passpoint != null)
            {
                var pk = new PublicKey(intermediate.passpoint);
            }

            var addresshashplusownersalt = new byte[12];
            Array.Copy(confbytes, 6, addresshashplusownersalt, 0, 4);
            if (intermediate.ownerentropy != null)
                Array.Copy(intermediate.ownerentropy, 0, addresshashplusownersalt, 4, 8);

            // derive encryption key material
            var derived = new byte[64];
            if (intermediate.passpoint != null)
                SCrypt.ComputeKey(intermediate.passpoint, addresshashplusownersalt, 1024, 1, 1, 1, derived);

            var derivedhalf2 = new byte[32];
            Array.Copy(derived, 32, derivedhalf2, 0, 32);

            var unencryptedpubkey = new byte[33];
            // recover the 0x02 or 0x03 prefix
            if (confbytes.Length > 18 && derived.Length > 63)
                unencryptedpubkey[0] = (byte) (confbytes[18] ^ (derived[63] & 0x01));

            // decrypt
            var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.ECB;
            aes.Key = derivedhalf2;
            var decryptor = aes.CreateDecryptor();

            decryptor.TransformBlock(confbytes, 19, 16, unencryptedpubkey, 1);
            decryptor.TransformBlock(confbytes, 19, 16, unencryptedpubkey, 1);
            decryptor.TransformBlock(confbytes, 19 + 16, 16, unencryptedpubkey, 17);
            decryptor.TransformBlock(confbytes, 19 + 16, 16, unencryptedpubkey, 17);

            // xor out the padding
            for (var i = 0; i < 32; i++) if (unencryptedpubkey.Length > i + 1)
                if (derived.Length > i) unencryptedpubkey[i + 1] ^= derived[i];

            // reconstitute the ECPoint
            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            ECPoint point;
            try {
                point = ps.Curve.DecodePoint(unencryptedpubkey);

                // multiply passfactor.  Result is going to be compressed.
                var pubpoint = point.Multiply(new BigInteger(1, intermediate.passfactor));

                // Do we want it uncompressed?  then we will have to uncompress it.
                var flagbyte = confbytes[5];
                if ((flagbyte & 0x20) == 0x00) {
                    pubpoint = ps.Curve.CreatePoint(pubpoint.X.ToBigInteger(), pubpoint.Y.ToBigInteger(), false);
                }

                // Convert to bitcoin address and check address hash.
                var generatedaddress = new PublicKey(pubpoint);

                // get addresshash
                var utf8 = new UTF8Encoding(false);
                var sha256 = new Sha256Digest();
                var generatedaddressbytes = utf8.GetBytes(generatedaddress.AddressBase58);
                sha256.BlockUpdate(generatedaddressbytes, 0, generatedaddressbytes.Length);
                var addresshashfull = new byte[32];
                sha256.DoFinal(addresshashfull, 0);
                sha256.BlockUpdate(addresshashfull, 0, 32);
                sha256.DoFinal(addresshashfull, 0);

                for (var i = 0; i < 4; i++) {
                    if (addresshashfull.Length > i && (confbytes.Length > i + 6 && addresshashfull[i] != confbytes[i + 6])) {
                        MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_passphrase_is_wrong_or_does_not_belong_to_this_confirmation_code_, Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_passphrase, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        return;
                    }
                }

                confirmIsValid(generatedaddress.AddressBase58);
            } catch {
                // Might throw an exception - not every 256-bit integer is a valid X coordinate
                MessageBox.Show(Resources.Bip38ConfValidator_btnConfirm_Click_This_passphrase_is_wrong_or_does_not_belong_to_this_confirmation_code_, Resources.Bip38ConfValidator_btnConfirm_Click_Invalid_passphrase, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

        }

        private void confirmIsValid(string address) {
            lblAddressHeader.Visible = true;
            lblAddressItself.Text = address;
            lblAddressItself.Visible = true;
            lblResult.Visible = true;

        }

    }
}
