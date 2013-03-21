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
using System.Drawing;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Windows.Forms;
using BtcAddress.Properties;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Casascius.Bitcoin;


namespace BtcAddress {
    public partial class MofNcalc : Form {
        public MofNcalc() {
            InitializeComponent();
        }

        private TextBox GetPartBox(int i)
        {
            if (txtPart1 != null && (txtPart2 != null && (txtPart3 != null && (txtPart4 != null && txtPart5 != null &&
                                                                               (txtPart6 != null &&
                                                                                (txtPart7 != null && txtPart8 != null))))))
            {
                var parts = new[]
                    {
                        txtPart1, txtPart2, txtPart3, txtPart4, txtPart5, txtPart6, txtPart7,
                        txtPart8
                    };
                if (parts.Length > i) return parts[i];
            }
        }


        private void textBox9_TextChanged(object sender, EventArgs e) {

        }

        private byte[] _targetPrivKey = null;

        private void btnGenerate_Clicxk(object sender, EventArgs e) {

            if (numPartsNeeded != null && (numPartsToGenerate != null && numPartsNeeded.Value > numPartsToGenerate.Value)) {
                MessageBox.Show(Resources.MofNcalc_btnGenerate_Clicxk_Number_of_parts_needed_exceeds_number_of_parts_to_generate_);
                return;
            }


            for (var i = 0; i < 8; i++) {
                var t = GetPartBox(i);
                t.Text = string.Empty;
                t.BackColor = Color.White;                
            }

            var mn = new MofN();

            if (_targetPrivKey == null) {
                if (numPartsNeeded != null)
                    if (numPartsToGenerate != null)
                        mn.Generate((int)numPartsNeeded.Value, (int)numPartsToGenerate.Value);
            } else {
                if (numPartsNeeded != null)
                    if (numPartsToGenerate != null)
                        mn.Generate((int)numPartsNeeded.Value, (int)numPartsToGenerate.Value, _targetPrivKey);
            }

            var j = 0;
            foreach (var kp in mn.GetKeyParts()) {
                if (kp != null) GetPartBox(j++).Text = kp;
            }

            if (txtPrivKey != null) txtPrivKey.Text = mn.BitcoinPrivateKey ?? "?";
            if (txtAddress != null) txtAddress.Text = mn.BitcoinAddress ?? "?";
        }

        public static List<equation> Solvesome(List<equation> ineq) {
            if (ineq == null) throw new ArgumentNullException("ineq");
            if (ineq.Count == 1) return ineq;

            var outeq = new List<equation>();

            for (var i = 1; i < ineq.Count; i++) {
                if (ineq.Count > i) outeq.Add(ineq[i].CombineAndReduce(ineq[0]));
            }
            return outeq;
        }

        private void btnDecode_Click(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            var mn = new MofN();

            for (var i = 0; i < 8; i++) {
                var t = GetPartBox(i);
                if (t.Text != null)
                {
                    var p = t.Text.Trim();

                    if (p == string.Empty || (mn.PartsAccepted >= mn.PartsNeeded && mn.PartsNeeded > 0)) {
                        t.BackColor = Color.White;
                    } else {
                        var result = mn.AddKeyPart(p);
                        if (result == null) {
                            t.BackColor = Color.LightGreen;
                        } else {
                            t.BackColor = System.Drawing.Color.Pink;
                        }
                    }
                }
            }

            if (mn.PartsAccepted >= mn.PartsNeeded && mn.PartsNeeded > 0) {
                mn.Decode();
                if (txtPrivKey != null) if (mn.BitcoinPrivateKey != null) txtPrivKey.Text = mn.BitcoinPrivateKey;
                if (txtAddress != null) if (mn.BitcoinAddress != null) txtAddress.Text = mn.BitcoinAddress;
            } else {
                MessageBox.Show(Resources.MofNcalc_btnDecode_Click_Not_enough_valid_parts_were_present_to_decode_an_address_);
            }


            

        }

        private void btnGenerateSpecific_Click(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");

            KeyPair k = null;

            try
            {
                if (txtPrivKey != null) k = new KeyPair(txtPrivKey.Text);
                _targetPrivKey = k.PrivateKeyBytes;
            }
            catch (Exception) {
                MessageBox.Show(Resources.MofNcalc_btnGenerateSpecific_Click_Not_a_valid_private_key_);
            }
            btnGenerate_Clicxk(sender, e);
            _targetPrivKey = null;
            
        }

        private void MofNcalc_Load(object sender, EventArgs e)
        {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            MessageBox.Show(Resources.MofNcalc_MofNcalc_Load_This_feature_is_experimental__a_proof_of_concept__and_the_key_format_will_probably_be_revised_heavily_before_this_ever_makes_it_into_production___Don_t_rely_on_it_to_secure_large_numbers_of_Bitcoins___If_you_use_it__make_sure_you_keep_a_copy_of_this_version_of_the_utility_in_case_the_m_of_n_format_is_changed_before_being_accepted_as_any_kind_of_standard_, "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }




    
}
