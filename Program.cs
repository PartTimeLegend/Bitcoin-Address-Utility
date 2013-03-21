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
using BtcAddress.Forms;

namespace BtcAddress {
    static class Program {

        public static Form1 AddressUtility = null;

        public static Base58Calc Base58Calc = null;

        public static MofNcalc MofNcalc = null;

        public static PpecKeygen IntermediateGen = null;

        public static KeyCombiner KeyCombiner = null;

        public static BtcAddress.Forms.DecryptKey DecryptKey = null;

        public static BtcAddress.Forms.Bip38ConfValidator ConfValidator = null;

        public static BtcAddress.Forms.EscrowTools EscrowTools = null;

        public static void ShowAddressUtility()
        {
            if (AddressUtility != null) AddressUtility = ShowForm<Form1>(AddressUtility);
        }

        public static void ShowBase58Calc()
        {
            if (Base58Calc != null) Base58Calc = ShowForm<Base58Calc>(Base58Calc);
        }

        public static void ShowMofNcalc()
        {
            if (MofNcalc != null) MofNcalc = ShowForm<MofNcalc>(MofNcalc);
        }

        public static void ShowIntermediateGen()
        {
            if (IntermediateGen != null) IntermediateGen = ShowForm<PpecKeygen>(IntermediateGen);
        }

        public static void ShowKeyCombiner()
        {
            if (KeyCombiner != null) KeyCombiner = ShowForm<KeyCombiner>(KeyCombiner);
        }

        public static void ShowConfValidator()
        {
            if (ConfValidator != null) ConfValidator = ShowForm(ConfValidator);
        }

        public static void ShowKeyDecrypter()
        {
            if (DecryptKey != null) DecryptKey = ShowForm(DecryptKey);
        }

        public static void ShowEscrowTools()
        {
            if (EscrowTools != null) EscrowTools = ShowForm(EscrowTools);
        }

        private static T ShowForm<T>(T currentform) where T : Form, new() {
            if (currentform == null || currentform.Visible == false) {
                var rv = new T();
                rv.Show();
                return rv;
            } else {
                currentform.Focus();
                return currentform;
            }
        }


        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main() {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            Application.Run(new KeyCollectionView());
        }
    }
}
