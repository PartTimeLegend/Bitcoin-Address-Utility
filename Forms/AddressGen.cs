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
using System.Linq;
using System.Windows.Forms;
using System.Threading;
using BtcAddress.Properties;
using Casascius.Bitcoin;

namespace BtcAddress.Forms {
    public partial class AddressGen : Form {
        public AddressGen() {
            InitializeComponent();
        }

        private enum GenChoices {
            Minikey, Wif, Encrypted, Deterministic, TwoFactor
        }

        private GenChoices _genChoice;

        private bool _generating = false;
        private bool _generatingEnded = false;

        private bool _stopRequested = false;

        private bool _permissionToCloseWindow = false;

        private bool _retainPrivateKeys = false;

        private string _userText;

        private int _remainingToGenerate = 0;

        private Thread _generationThread = null;

        public List<KeyCollectionItem> GeneratedItems = new List<KeyCollectionItem>();

        private Bip38Intermediate[] _intermediatesForGeneration;

        private int _intermediateIdx;

        private void rdoWalletType_CheckedChanged(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            if (txtTextInput != null)
            {
                txtTextInput.Text = "";
                if (rdoEncrypted != null)
                    if (rdoDeterministicWallet != null)
                        txtTextInput.Visible = (rdoDeterministicWallet.Checked || rdoEncrypted.Checked);
            }
            if (lblTextInput != null)
            {
                if (rdoDeterministicWallet != null)
                {
                    if (rdoEncrypted != null)
                    {
                        if (rdoTwoFactor != null)
                        {
                            lblTextInput.Visible = (rdoDeterministicWallet.Checked || rdoEncrypted.Checked || rdoTwoFactor.Checked);
                            if (rdoDeterministicWallet.Checked) {
                                if (
                                    Resources.AddressGen_rdoWalletType_CheckedChanged_Seed_for_deterministic_generation !=
                                    null)
                                    lblTextInput.Text = Resources.AddressGen_rdoWalletType_CheckedChanged_Seed_for_deterministic_generation;
                            } else if (rdoEncrypted.Checked) {
                                if (
                                    Resources
                                        .AddressGen_rdoWalletType_CheckedChanged_Encryption_passphrase_or_Intermediate_Code !=
                                    null)
                                    lblTextInput.Text = Resources.AddressGen_rdoWalletType_CheckedChanged_Encryption_passphrase_or_Intermediate_Code;
                            } else if (rdoTwoFactor.Checked) {
                                var icodect = ScanClipboardForIntermediateCodes().Count;
                                if (icodect == 0) {
                                    if (
                                        Resources
                                            .AddressGen_rdoWalletType_CheckedChanged_Copy_one_or_more_intermediate_codes_to_the_clipboard_ !=
                                        null)
                                        lblTextInput.Text = Resources.AddressGen_rdoWalletType_CheckedChanged_Copy_one_or_more_intermediate_codes_to_the_clipboard_;
                                } else {
                                    lblTextInput.Text = icodect + Resources.AddressGen_rdoWalletType_CheckedChanged__intermediate_codes_found_on_clipboard_;
                                }
                            }
                        }
                    }
                }
            }
            if (rdoEncrypted != null) chkRetainPrivKey.Visible = (rdoEncrypted.Checked);
        }

        private void AddressGen_FormClosing(object sender, FormClosingEventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");
            if (_permissionToCloseWindow) return;
            if (_generating) {
                if (MessageBox.Show(Resources.AddressGen_AddressGen_FormClosing_Cancel_and_abandon_generation_in_progress_, Resources.AddressGen_AddressGen_FormClosing_Abort_generation, MessageBoxButtons.YesNo) == DialogResult.No) {
                    e.Cancel = true;
                } else {
                    _stopRequested = true;
                    if (_generationThread != null && _generationThread.ThreadState == ThreadState.Running)
                    {
                        _generationThread.Join();
                        if (GeneratedItems != null) GeneratedItems.Clear();
                    }
                }
            }
        }

        private void btnGenerateAddresses_Click(object sender, EventArgs e) {
            if (sender == null) throw new ArgumentNullException("sender");
            if (e == null) throw new ArgumentNullException("e");

            if (_generating) {
                _stopRequested = true;
                if (btnGenerateAddresses != null) btnGenerateAddresses.Text = Resources.AddressGen_btnGenerateAddresses_Click_Stopping___;
                return;
            }

            if (txtTextInput != null && (rdoEncrypted != null && (rdoEncrypted.Checked && txtTextInput.Text == string.Empty))) {
                MessageBox.Show(Resources.AddressGen_btnGenerateAddresses_Click_An_encryption_passphrase_is_required__Choose_a_different_option_if_you_don_t_want_encrypted_keys_,
                    Resources.AddressGen_btnGenerateAddresses_Click_Passphrase_missing, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (txtTextInput != null && (rdoDeterministicWallet != null && (rdoDeterministicWallet.Checked && txtTextInput.Text == string.Empty))) {
                MessageBox.Show(Resources.AddressGen_btnGenerateAddresses_Click_A_deterministic_seed_is_required___If_you_do_not_intend_to_create_a_deterministic_wallet_or_know_what_one_is_used_for__it_is_recommended_you_choose_one_of_the_other_options___An_inappropriate_seed_can_result_in_the_unexpected_theft_of_funds_,
                    Resources.AddressGen_btnGenerateAddresses_Click_Seed_missing, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (rdoTwoFactor.Checked) {
                // Read the clipboard for intermediate codes
                var intermediates = ScanClipboardForIntermediateCodes();
                if (intermediates.Count == 0) {
                    MessageBox.Show(Resources.AddressGen_btnGenerateAddresses_Click_No_valid_intermediate_codes_were_found_on_the_clipboard___Intermediate_codes_are_typically_sent_to_you_from_someone_else_desiring_paper_wallets__or_from_your_mobile_phone___Copy_the_received_intermediate_codes_to_the_clipboard__and_try_again___Address_Generator_automatically_detects_valid_intermediate_codes_and_ignores_everything_else_on_the_clipboard, Resources.AddressGen_btnGenerateAddresses_Click_No_intermediate_codes_found, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                _intermediatesForGeneration = intermediates.ToArray();
                _intermediateIdx = 0;

            } else {
                _intermediatesForGeneration = null;
            }


            _generationThread = new Thread(GenerationThreadProcess);
            if (numGenCount != null) _remainingToGenerate = (int)numGenCount.Value;
            if (txtTextInput != null && txtTextInput.Text != null) _userText = txtTextInput.Text;
            if (chkRetainPrivKey != null) _retainPrivateKeys = chkRetainPrivKey.Checked;

            if (rdoDeterministicWallet != null && rdoDeterministicWallet.Checked) _genChoice = GenChoices.Deterministic;
            if (rdoEncrypted != null && rdoEncrypted.Checked) {
                _genChoice = GenChoices.Encrypted;
                // intermediate codes start with "passphrasek" thru "passphrases"
                if (txtTextInput != null && txtTextInput.Text != null)
                {
                    var ti = txtTextInput.Text.Trim();
                }
                if (txtTextInput != null) txtTextInput.UseSystemPasswordChar = true;
            }
            if (rdoMiniKeys != null && rdoMiniKeys.Checked) _genChoice = GenChoices.Minikey;
            if (rdoRandomWallet != null && rdoRandomWallet.Checked) _genChoice = GenChoices.Wif;
            if (rdoTwoFactor.Checked) {
                _genChoice = GenChoices.TwoFactor;
            }

            timer1.Interval = 250;
            timer1.Enabled = true;
            _generating = true;
            _generatingEnded = false;
            _stopRequested = false;
            btnGenerateAddresses.Text = Resources.AddressGen_btnGenerateAddresses_Click_Cancel;
            SetControlsEnabled(false);
            toolStripProgressBar1.Visible = true;
            _generationThread.Start();

        }

        private void SetControlsEnabled(bool enabled) {
            foreach (var c in Controls)
            {
                var box = c as TextBox;
                if (box != null) {
                    box.Enabled = enabled;
                } else
                {
                    var down = c as NumericUpDown;
                    if (down != null) {
                        down.Enabled = enabled;
                    }
                }
            }
            foreach (var c in groupBox1.Controls)
            {
                var button = c as RadioButton;
                if (button != null) {
                    button.Enabled = enabled;
                }
            }
        }

        /// <summary>
        /// Code which is actually run on the generation thread.
        /// </summary>
        private void GenerationThreadProcess() {

            Bip38Intermediate intermediate = null;
            if (_genChoice == GenChoices.Encrypted) {
                if (_userText != null)
                    intermediate = new Bip38Intermediate(_userText, Bip38Intermediate.Interpretation.Passphrase);
            }

            var detcount = 1;

            while (_remainingToGenerate > 0 && _stopRequested == false) {
                KeyCollectionItem newitem = null;

                Bip38KeyPair ekp = null;
                switch (_genChoice) {
                    case GenChoices.Minikey:
                        var mkp = MiniKeyPair.CreateRandom(ExtraEntropy.GetEntropy());
                        if (mkp == null) throw new ArgumentNullException("mkp");
                        newitem = new KeyCollectionItem(mkp);
                        break;
                    case GenChoices.Wif:
                        var kp = KeyPair.Create(ExtraEntropy.GetEntropy());
                        if (kp == null) throw new ArgumentNullException("kp");
                        newitem = new KeyCollectionItem(kp);
                        break;
                    case GenChoices.Deterministic:
                        kp = KeyPair.CreateFromString(_userText + detcount);
                        detcount++;
                        if (kp != null) newitem = new KeyCollectionItem(kp);
                        break;
                    case GenChoices.Encrypted:
                        if (intermediate != null)
                        {
                            ekp = new Bip38KeyPair(intermediate);
                            newitem = new KeyCollectionItem(ekp);
                        }
                        break;
                    case GenChoices.TwoFactor:
                        if (_intermediatesForGeneration != null)
                        {
                            if (_intermediatesForGeneration.Length > _intermediateIdx++)
                                ekp = new Bip38KeyPair(_intermediatesForGeneration[_intermediateIdx++]);
                            if (_intermediateIdx >= _intermediatesForGeneration.Length) _intermediateIdx = 0;
                        }
                        newitem = new KeyCollectionItem(ekp);
                        
                        break;
                }

                lock (GeneratedItems) {
                    GeneratedItems.Add(newitem);
                    _remainingToGenerate--;
                }
            }
            _generatingEnded = true;
        }

        private List<Bip38Intermediate> ScanClipboardForIntermediateCodes() {
            var cliptext = Clipboard.GetText(TextDataFormat.UnicodeText);
            var objects = StringInterpreter.InterpretBatch(cliptext);
            var intermediates = new List<Bip38Intermediate>(
                objects.OfType<Bip38Intermediate>());
            return intermediates;
        }

        private void timer1_Tick(object sender, EventArgs e) {
            if (_generatingEnded) {
                _generating = false;
                _generatingEnded = false;
                toolStripProgressBar1.Value = 0;
                toolStripProgressBar1.Visible = false;
                toolStripStatusLabel1.Text = string.Empty;

                btnGenerateAddresses.Text = Resources.AddressGen_timer1_Tick_Generate_Addresses;
                timer1.Enabled = false;
                SetControlsEnabled(true);
                if (_stopRequested == false) {
                    _permissionToCloseWindow = true;
                    Close();
                } else if (GeneratedItems.Count > 0) {
                    toolStripStatusLabel1.Text = Resources.AddressGen_timer1_Tick_Keys_generated__ + GeneratedItems.Count;
                    if (_permissionToCloseWindow) {
                        Close();
                        return;
                    } else if (MessageBox.Show(Resources.AddressGen_timer1_Tick_Keep_the_ + GeneratedItems.Count + Resources.AddressGen_timer1_Tick__generated_keys_, Resources.AddressGen_timer1_Tick_Cancel_generation, MessageBoxButtons.YesNo) == System.Windows.Forms.DialogResult.No) {
                        GeneratedItems.Clear();
                    }
                    _permissionToCloseWindow = true;
                    Close();
                }
                return;
            }

            if (_generating) {
                var generated = 0;
                var totaltogenerate = 0;
                if (GeneratedItems != null)
                    lock (GeneratedItems) {
                        generated = GeneratedItems.Count;
                        totaltogenerate = generated + _remainingToGenerate;
                    }
                if (rdoEncrypted != null && (generated == 0 && rdoEncrypted.Checked)) {
                    toolStripStatusLabel1.Text = Resources.AddressGen_timer1_Tick_Hashing_the_passphrase___;
                } else {
                    toolStripStatusLabel1.Text = Resources.AddressGen_timer1_Tick_Keys_generated__ + generated;
                    toolStripProgressBar1.Maximum = totaltogenerate;
                    toolStripProgressBar1.Value = generated;
                }
            }
        }
    }
}
