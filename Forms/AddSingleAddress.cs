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
    public partial class AddSingleAddress : Form {
        public AddSingleAddress() {
            InitializeComponent();
        }

        public object Result;

        private void button1_Click(object sender, EventArgs e) {
            if (textBox1.Text == string.Empty) {
                MessageBox.Show(Resources.AddSingleAddress_button1_Click_Enter_a_key_first_);
                return;
            }

            if (btnGoMulti.Visible)
            {
                if (textBox1.Text != null) Result = StringInterpreter.Interpret(textBox1.Text);
                if (Result == null)
                {
                    MessageBox.Show(Resources.AddSingleAddress_button1_Click_Unrecognized_or_invalid_string);
                }
                else
                {
                    Close();
                }
            }
            else
            {
                if (textBox1.Text != null) Result = StringInterpreter.InterpretBatch(textBox1.Text);
                if (Result == null)
                {
                    MessageBox.Show(Resources.AddSingleAddress_button1_Click_Unrecognized_or_invalid_string);
                }
                else
                {
                    Close();
                }
            }
        }

        private void btnGoMulti_Click(object sender, EventArgs e) {
            textBox1.Focus();
            textBox1.Multiline = true;
            btnGoMulti.Visible = false;
            lblEnterWhat.Text = Resources.AddSingleAddress_btnGoMulti_Click_Enter_or_paste_text__Addresses_and_keys_will_be_picked_out_;
            this.Text = Resources.AddSingleAddress_btnGoMulti_Click_Add_Multiple_Addresses;
            if (this.Height < 500) this.Height = 500;
            AcceptButton = null;
        }


    }
}
