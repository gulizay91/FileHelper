using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ByteAndHash
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btnFileOpen_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog1 = new OpenFileDialog();
            if(openFileDialog1.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                string pathFile = openFileDialog1.FileName;
                //MessageBox.Show(pathFile);
                txtbxResult.AppendText("Path: " + pathFile + Environment.NewLine);

                var byteArray = File.ReadAllBytes(pathFile);
                var md5Hash = HashUtility.ComputeMD5Hash(byteArray);
                txtbxResult.AppendText("Md5Hash: " + md5Hash + Environment.NewLine);

                string base64String = Convert.ToBase64String(byteArray, 0, byteArray.Length);
                txtbxResult.AppendText("Base64String: " + base64String);
            }
        }
    }
}
