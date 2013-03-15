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
using System.Windows.Forms;
using BtcAddress.Properties;
using Casascius.Bitcoin;

namespace BtcAddress.Forms {
    public partial class Base58Calc : Form {
        public Base58Calc() {
            InitializeComponent();
        }

        private void txtHex_TextChanged(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            if (txtHex.ContainsFocus == false) return;
            if (txtHex.Text != null)
            {
                var bytes = Util.HexStringToBytes(txtHex.Text);
                if (useChecksumToolStripMenuItem.Checked) {
                    if (bytes != null) txtBase58.Text = Util.ByteArrayToBase58Check(bytes);
                } else {
                    if (bytes != null) txtBase58.Text = Base58.FromByteArray(bytes);
                }
            }

            UpdateByteCounts();
        }

        private void txtBase58_TextChanged(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            if (txtBase58.ContainsFocus == false) return;
            var bytes = new byte[] {};
            if (useChecksumToolStripMenuItem != null && useChecksumToolStripMenuItem.Checked) {
                if (txtBase58.Text != null) bytes = Util.Base58CheckToByteArray(txtBase58.Text);
            } else {
                if (txtBase58.Text != null) bytes = Base58.ToByteArray(txtBase58.Text);
            }
            var hex = "invalid";
            if (bytes != null) {
                hex = Util.ByteArrayToString(bytes);
            }
            if (hex != null) txtHex.Text = hex;
            UpdateByteCounts();
        }

        private void UpdateByteCounts() {
            lblByteCounts.Text = Resources.Base58Calc_UpdateByteCounts_Bytes__ + Util.HexStringToBytes(txtHex.Text).Length + Resources.Base58Calc_UpdateByteCounts___Base58_length__ + txtBase58.Text.Length;

        }

        private void useChecksumToolStripMenuItem_Click(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            useChecksumToolStripMenuItem.Checked = !useChecksumToolStripMenuItem.Checked;
            // pretend that whatever had the focus was just changed
            if (txtBase58.Focused) {
                txtBase58_TextChanged(txtBase58, null);
            } else if (txtHex.Focused) {
                txtHex_TextChanged(txtHex, null);
            }

        }

    }
}
