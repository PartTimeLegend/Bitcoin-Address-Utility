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
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using BtcAddress.Properties;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Casascius.Bitcoin;

namespace BtcAddress {
    public partial class KeyCombiner : Form {
        public KeyCombiner() {
            InitializeComponent();
        }

        private void btnCombine_Click(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            // What is input #1?

            if (txtInput1.Text != null)
            {
                var input1 = txtInput1.Text;
                if (txtInput2.Text != null)
                {
                    var input2 = txtInput2.Text;
                    PublicKey pub1 = null;
                    PublicKey pub2 = null;
                    KeyPair kp1 = null;
                    KeyPair kp2 = null;


                    if (KeyPair.IsValidPrivateKey(input1)) {
                        pub1 = kp1 = new KeyPair(input1);
                    } else if (PublicKey.IsValidPublicKey(input1)) {
                        pub1 = new PublicKey(input1);
                    } else {
                        MessageBox.Show(Resources.KeyCombiner_btnCombine_Click_Input_key__1_is_not_a_valid_Public_Key_or_Private_Key_Hex, Resources.KeyCombiner_btnCombine_Click_Can_t_combine, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    if (KeyPair.IsValidPrivateKey(input2)) {
                        pub2 = kp2 = new KeyPair(input2);
                    } else if (PublicKey.IsValidPublicKey(input2)) {
                        pub2 = new PublicKey(input2);
                    } else {
                        MessageBox.Show(Resources.KeyCombiner_btnCombine_Click_Input_key__2_is_not_a_valid_Public_Key_or_Private_Key_Hex, Resources.KeyCombiner_btnCombine_Click_Can_t_combine, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    if (kp1 == null && kp2 == null && rdoAdd.Checked == false) {
                        MessageBox.Show(Resources.KeyCombiner_btnCombine_Click_Can_t_multiply_two_public_keys___At_least_one_of_the_keys_must_be_a_private_key_, 
                                        Resources.KeyCombiner_btnCombine_Click_Can_t_combine, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    if (pub1.IsCompressedPoint != pub2.IsCompressedPoint) {
                        MessageBox.Show(Resources.KeyCombiner_btnCombine_Click_Can_t_combine_a_compressed_key_with_an_uncompressed_key_, Resources.KeyCombiner_btnCombine_Click_Can_t_combine, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }

                    if (pub1.AddressBase58 == pub2.AddressBase58) {
                        if (MessageBox.Show(Resources.KeyCombiner_btnCombine_Click_Both_of_the_key_inputs_have_the_same_public_key_hash___You_can_continue__but_the_results_are_probably_going_to_be_wrong___You_might_have_provided_the_wrong_information__such_as_two_parts_from_the_same_side_of_the_transaction__instead_of_one_part_from_each_side___Continue_anyway_, "Duplicate Key Warning", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) {
                                                return;
                                            }

                    }

                    var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");

                    // Combining two private keys?
                    if (kp1 != null && kp2 != null) {
                        if (kp1.PrivateKeyBytes != null)
                        {
                            var e1 = new BigInteger(1, kp1.PrivateKeyBytes);
                            if (kp2.PrivateKeyBytes != null)
                            {
                                var e2 = new BigInteger(1, kp2.PrivateKeyBytes);
                                if (ps != null && ps.N != null)
                                {
                                    var ecombined = (rdoAdd.Checked ? e1.Add(e2) : e1.Multiply(e2)).Mod(ps.N);


                                    Debug.WriteLine(kp1.PublicKeyHex);
                                    Debug.WriteLine(kp2.PublicKeyHex);
                                    if (ecombined != null)
                                    {
                                        var kpcombined = new KeyPair(
                                            Util.Force32Bytes(ecombined.ToByteArrayUnsigned()), kp1.IsCompressedPoint);

                                        if (txtOutputAddress != null)
                                            if (kpcombined.AddressBase58 != null)
                                                txtOutputAddress.Text = kpcombined.AddressBase58;
                                        if (txtOutputPubkey != null)
                                            if (kpcombined.PublicKeyHex != null)
                                                txtOutputPubkey.Text = kpcombined.PublicKeyHex.Replace(" ", string.Empty);
                                        if (kpcombined.PrivateKeyBase58 != null)
                                            txtOutputPriv.Text = kpcombined.PrivateKeyBase58;
                                    }
                                }
                            }
                        }
                    } else if (kp1 != null || kp2 != null) {
                        // Combining one public and one private

                        var priv = kp1 ?? kp2;
                        var pub = kp1 == null ? pub1 : pub2;

                        var point = pub.GetECPoint();
                        if (point == null) throw new ArgumentNullException("point");

                        if (priv.PrivateKeyBytes != null)
                        {
                            var combined = rdoAdd != null && rdoAdd.Checked ? point.Add(priv.GetECPoint()) : point.Multiply(new BigInteger(1, priv.PrivateKeyBytes));
                            if (combined.Y != null && combined.X != null)
                            {
                                var combinedc = ps.Curve.CreatePoint(combined.X.ToBigInteger(),
                                                                     combined.Y.ToBigInteger(), priv.IsCompressedPoint);
                                if (combinedc == null) throw new ArgumentNullException("combinedc");
                                var pkcombined = new PublicKey(combinedc.GetEncoded());
                                if (txtOutputAddress != null) txtOutputAddress.Text = pkcombined.AddressBase58;
                                if (txtOutputPubkey != null)
                                    txtOutputPubkey.Text = pkcombined.PublicKeyHex.Replace(" ", string.Empty);
                            }
                        }
                        txtOutputPriv.Text = Resources.KeyCombiner_btnCombine_Click_Only_available_when_combining_two_private_keys;
                    } else {
                        // Adding two public keys
                        var combined = pub1.GetECPoint().Add(pub2.GetECPoint());
                        if (combined != null && (combined.X != null && combined.Y != null))
                        {
                            var combinedc = ps.Curve.CreatePoint(combined.X.ToBigInteger(),
                                                                 combined.Y.ToBigInteger(), pub1.IsCompressedPoint);
                            if (combinedc != null)
                            {
                                var pkcombined = new PublicKey(combinedc.GetEncoded());
                                if (txtOutputAddress != null) txtOutputAddress.Text = pkcombined.AddressBase58;
                                if (txtOutputPubkey != null && pkcombined.PublicKeyHex != null)
                                    txtOutputPubkey.Text = pkcombined.PublicKeyHex.Replace(" ", string.Empty);
                            }
                        }
                        txtOutputPriv.Text = Resources.KeyCombiner_btnCombine_Click_Only_available_when_combining_two_private_keys;
                    }
                }
            }
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            MessageBox.Show(Resources.KeyCombiner_linkLabel1_LinkClicked_EC_Addition_should_not_be_used_for_two_factor_storage___Use_multiplication_instead__Addition_is_safe_when_employing_a_vanity_pool_to_generate_vanity_addresses__and_is_required_for_vanity_address_generators_to_achieve_GPU_accelerated_performance___For_some_other_uses__addition_is_unsafe_due_to_its_reversibility__so_always_use_multiplication_instead_wherever_possible_);
        }
    }
}
