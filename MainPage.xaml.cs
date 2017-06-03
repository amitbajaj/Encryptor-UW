using System;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Popups;
using Windows.Storage;
using Encryption;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace Encryptor_UW
{
    /// <summary>
    /// The main page to encrypt and decrypt text
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private String GoogleAuthJSON;
        public MainPage()
        {
            this.InitializeComponent();
            ApplicationDataContainer adc = ApplicationData.Current.LocalSettings.CreateContainer("GoogleDrive", ApplicationDataCreateDisposition.Always);
            object obj;
            if (adc.Values.TryGetValue("json", out obj))
            {
                GoogleAuthJSON = (String)obj;
            }
            else
            {
                GoogleAuthJSON = "";
            }
            Window.Current.SizeChanged += Current_SizeChanged;
            txtData.MaxHeight = Window.Current.Bounds.Height - 140;
        }

        private void Current_SizeChanged(object sender, Windows.UI.Core.WindowSizeChangedEventArgs e)
        {
            txtData.MaxHeight = e.Size.Height - 140;
        }

        private async void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            Encryptor enc = new Encryptor();
            try
            {
                String encryptedText = Convert.ToBase64String(enc.EncryptStringToBytes_AesIV(txtData.Text, txtPass.Password));
                txtData.Text = encryptedText;
            }
            catch (Exception ex)
            {
                var alert = new MessageDialog(ex.Message);
                await alert.ShowAsync();
            }
            enc = null;
        }

        private async void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            Encryptor enc = new Encryptor();
            try
            {
                String encryptedText = enc.DecryptStringFromBytes_AesIV(txtData.Text, txtPass.Password);
                txtData.Text = encryptedText;
            }
            catch (Exception ex)
            {
                var alert = new MessageDialog(ex.Message);
                await alert.ShowAsync();
            }
            enc = null;
        }
        private async void btnReadFromGoogle_Click(object sender, RoutedEventArgs e)
        {
            GoogleDriveHelper gh = new GoogleDriveHelper();
            if (await gh.LoginToGoogle(GoogleAuthJSON))
            {
                GoogleAuthJSON = gh.GoogleAuthJSON;
                ApplicationDataContainer adc = ApplicationData.Current.LocalSettings.CreateContainer("GoogleDrive", ApplicationDataCreateDisposition.Always);
                if (adc.Values.Keys.Contains("json"))
                {
                    adc.Values["json"] = gh.GoogleAuthJSON;
                }
                else
                {
                    adc.Values.Add("json", gh.GoogleAuthJSON);
                }
                
                if (gh.CreateService())
                {
                    if (gh.ReadFile("TextEncryptor"))
                    {
                        txtData.Text = gh.fileData;
                        var alert = new MessageDialog("Successfully read file from Google!");
                        await alert.ShowAsync();
                    }
                    else
                    {
                        var alert = new MessageDialog("Error reading file from Google!");
                        await alert.ShowAsync();
                    }
                }
                else
                {
                    var alert = new MessageDialog("Error creating Google Drive Service!");
                    await alert.ShowAsync();
                }
            }
            else
            {
                var alert = new MessageDialog("Error connecting to Google!");
                await alert.ShowAsync();
            }
        }

        private async void btnWriteToGoogle_Click(object sender, RoutedEventArgs e)
        {
            GoogleDriveHelper gh = new GoogleDriveHelper();
            if (await gh.LoginToGoogle(GoogleAuthJSON))
            {
                GoogleAuthJSON = gh.GoogleAuthJSON;
                ApplicationDataContainer adc = ApplicationData.Current.LocalSettings.CreateContainer("GoogleDrive", ApplicationDataCreateDisposition.Always);
                if (adc.Values.Keys.Contains("json"))
                {
                    adc.Values["json"] = gh.GoogleAuthJSON;
                }
                else
                {
                    adc.Values.Add("json", gh.GoogleAuthJSON);
                }
                if (gh.CreateService())
                {
                    if (gh.WriteFile("TextEncryptor", txtData.Text))
                    {
                        var alert = new MessageDialog("Successfully wrote file to Google!");
                        await alert.ShowAsync();
                    }
                    else
                    {
                        var alert = new MessageDialog("Error writing file to Google!");
                        await alert.ShowAsync();
                    }
                }
                else
                {
                    var alert = new MessageDialog("Error creating Google Drive Service!");
                    await alert.ShowAsync();
                }
            }
            else
            {
                var alert = new MessageDialog("Error connecting to Google!");
                await alert.ShowAsync();
            }
        }

    }
}
