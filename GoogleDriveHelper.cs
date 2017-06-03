using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Drive.v3;
using Google.Apis.Services;
using Google.Apis.Util.Store;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.Resources.Core;
using Windows.Data.Json;
using Windows.Foundation;
using Windows.Security.Authentication.Web;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.System;

namespace Encryption
{
    class GoogleDriveHelper
    {
        static String[] Scopes = { DriveService.Scope.DriveFile };
        static String ApplicationName = "Password Protect";
        private UserCredential userCredential;
        private DriveService driveService;
        private Google.Apis.Drive.v3.Data.File driveFile;
        public String tokenString;
        public String GoogleAuthJSON;
        public String fileData;

        String clientID; //= "11399004738-s5gbs77m93l1p8k5emj489b0ou1acg4q.apps.googleusercontent.com";
        String clientSecret; // = "Hp7F0PLIaDVu54AeO_GlhWZt";
        const String redirectURI = "http://localhost/";
        const String authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        const String tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";

        public GoogleDriveHelper()
        {
            ReadCredentials();
        }

        private async void ReadCredentials()
        {
            ResourceContext rc = ResourceContext.GetForViewIndependentUse();
            ResourceMap map = ResourceManager.Current.MainResourceMap;
            ResourceCandidate resource = map.GetValue("Files/Assets/api_credentials.json", rc);
            Debug.WriteLine("I am in the constructor!!");

            Debug.WriteLine(resource.ValueAsString);
            Stream file = (await resource.GetValueAsStreamAsync()).AsStreamForRead();
            file.Position = 0;
            byte[] bytes = new byte[file.Length];
            Debug.WriteLine("File Length is : " + file.Length);
            file.Read(bytes, 0, (int)file.Length);
            String json = System.Text.Encoding.UTF8.GetString(bytes);
            int index = json.IndexOf('{');
            json = json.Substring(index);
            JsonObject creds = JsonObject.Parse(json);
            clientID = creds.GetNamedString("clientID");
            clientSecret = creds.GetNamedString("clientSecret");
        }

        public async System.Threading.Tasks.Task<bool> LoginToGoogle(String gaJSON)
        {
            if (gaJSON.Length == 0)
            {
                try
                {
                    // Generates state and PKCE values.
                    string state = randomDataBase64url(32);
                    string code_verifier = randomDataBase64url(32);
                    string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
                    const string code_challenge_method = "S256";

                    // Stores the state and code_verifier values into local settings.
                    // Member variables of this class may not be present when the app is resumed with the
                    // authorization response, so LocalSettings can be used to persist any needed values.
                    ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
                    localSettings.Values["state"] = state;
                    localSettings.Values["code_verifier"] = code_verifier;

                    // Creates the OAuth 2.0 authorization request.
                    string authorizationRequest = string.Format("{0}?access_type=offline&response_type=code&scope=https:%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.file&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
                        authorizationEndpoint,
                        System.Uri.EscapeDataString(redirectURI),
                        clientID,
                        state,
                        code_challenge,
                        code_challenge_method);

                    // Opens the Authorization URI in the browser


                    WebAuthenticationResult WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                                            WebAuthenticationOptions.None,
                                            new Uri(authorizationRequest),
                                            new Uri(redirectURI));
                    if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                    {
                        Uri authorizationResponse = new Uri(WebAuthenticationResult.ResponseData.ToString());
                        string queryString = authorizationResponse.Query;
                        tokenString = queryString.Split('=')[1];
                        Debug.WriteLine("MainPage received authorizationResponse: " + authorizationResponse);

                        // Parses URI params into a dictionary
                        // ref: http://stackoverflow.com/a/11957114/72176

                        Dictionary<string, string> queryStringParams =
                                queryString.Substring(1).Split('&')
                                     .ToDictionary(c => c.Split('=')[0],
                                                   c => Uri.UnescapeDataString(c.Split('=')[1]));
                        if (queryStringParams.ContainsKey("error"))
                        {
                            Debug.WriteLine(String.Format("OAuth authorization error: {0}.", queryStringParams["error"]));
                            return false;
                        }

                        if (!queryStringParams.ContainsKey("code")
                            || !queryStringParams.ContainsKey("state"))
                        {
                            Debug.WriteLine("Malformed authorization response. " + queryString);
                            return false;
                        }

                        // Gets the Authorization code & state
                        string code = queryStringParams["code"];
                        string incoming_state = queryStringParams["state"];

                        // Retrieves the expected 'state' value from local settings (saved when the request was made).
                        string expected_state = (String)localSettings.Values["state"];

                        // Compares the receieved state to the expected value, to ensure that
                        // this app made the request which resulted in authorization
                        if (incoming_state != expected_state)
                        {
                            Debug.WriteLine(String.Format("Received request with invalid state ({0})", incoming_state));
                            return false;
                        }
                        // Resets expected state value to avoid a replay attack.
                        localSettings.Values["state"] = null;

                        // Authorization Code is now ready to use!
                        Debug.WriteLine(Environment.NewLine + "Authorization code: " + code);
                        code_verifier = (String)localSettings.Values["code_verifier"];
                        if (await performCodeExchangeAsync(code, code_verifier))
                        {
                            return createCredential();
                        }
                        else
                        {
                            return false;
                        };

                    }
                    else if (WebAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp)
                    {
                        return false;
                    }
                    else
                    {
                        return false;
                    }
                }
                catch (Exception Error)
                {
                    Debug.WriteLine(Error.InnerException);
                    return false;
                }

            }
            else
            {
                if (await refreshToken(gaJSON))
                {
                    return createCredential();
                }
                else
                {
                    return false;
                }
            }

            
        }

        async Task<bool> performCodeExchangeAsync(string code, string code_verifier)
        {
            // Builds the Token request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&client_secret={3}&code_verifier={4}&scope=&grant_type=authorization_code",
                code,
                System.Uri.EscapeDataString(redirectURI),
                clientID,
                clientSecret,
                code_verifier
                );
            StringContent content = new StringContent(tokenRequestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

            // Performs the authorization code exchange.
            HttpClientHandler handler = new HttpClientHandler();
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);
            Debug.WriteLine(Environment.NewLine + "Exchanging code for tokens...");
            HttpResponseMessage response = await client.PostAsync(tokenEndpoint, content);
            string responseString = await response.Content.ReadAsStringAsync();
            Debug.WriteLine(responseString);

            if (!response.IsSuccessStatusCode)
            {
                Debug.WriteLine("Authorization code exchange failed.");
                return false;
            }


            JsonObject tokens = JsonObject.Parse(responseString);
            DateTime current = DateTime.UtcNow;
            DateTime expiry = DateTime.UtcNow.AddSeconds(tokens.GetNamedNumber("expires_in"));
            tokens.SetNamedValue("issued_utc", JsonValue.CreateStringValue(DateTime.UtcNow.ToString()));
            tokens.SetNamedValue("expiry_utc", JsonValue.CreateStringValue(expiry.ToString()));
            GoogleAuthJSON = tokens.ToString();
            //string accessToken = tokens.GetNamedString("access_token");
            TokenResponse tokenParameter = new TokenResponse
            {
                RefreshToken = tokens.GetNamedString("refresh_token"),
                TokenType = tokens.GetNamedString("token_type"),
                ExpiresInSeconds = (long)tokens.GetNamedNumber("expires_in"),
                AccessToken = tokens.GetNamedString("access_token"),
                IssuedUtc = DateTime.Parse(tokens.GetNamedString("issued_utc"))
            };

            ClientSecrets secrets = new ClientSecrets()
            {
                ClientId = clientID,
                ClientSecret = clientSecret
            };
            userCredential = new UserCredential(new GoogleAuthorizationCodeFlow(
                new GoogleAuthorizationCodeFlow.Initializer
                {
                    ClientSecrets = secrets
                }),
                "user",
                tokenParameter);

            return true;
        }


        async Task<bool> refreshToken(string authJSON)
        {
            // Builds the Token request
            JsonObject tokens = JsonObject.Parse(authJSON);
            string code = tokens.GetNamedString("refresh_token");
            DateTime expiry = DateTime.Parse(tokens.GetNamedString("expiry_utc"));
            if (expiry <= DateTime.UtcNow)
            {
                Debug.WriteLine("Token has expired.. Refreshing now...");
                string tokenRequestBody = string.Format("refresh_token={0}&client_id={1}&client_secret={2}&grant_type=refresh_token",
                    code,
                    clientID,
                    clientSecret
                    );
                StringContent content = new StringContent(tokenRequestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

                // Performs the authorization code exchange.
                HttpClientHandler handler = new HttpClientHandler();
                handler.AllowAutoRedirect = true;
                HttpClient client = new HttpClient(handler);
                Debug.WriteLine(Environment.NewLine + "Refreshing the token...");
                HttpResponseMessage response = await client.PostAsync(tokenEndpoint, content);
                string responseString = await response.Content.ReadAsStringAsync();
                Debug.WriteLine(responseString);

                if (!response.IsSuccessStatusCode)
                {
                    Debug.WriteLine("Token refresh failed.");
                    return false;
                }
                JsonObject newToken = JsonObject.Parse(responseString);
                DateTime current = DateTime.UtcNow;
                expiry = DateTime.UtcNow.AddSeconds(newToken.GetNamedNumber("expires_in"));
                tokens.SetNamedValue("access_token", newToken.GetNamedValue("access_token"));
                tokens.SetNamedValue("expires_in", newToken.GetNamedValue("expires_in"));
                tokens.SetNamedValue("issued_utc", JsonValue.CreateStringValue(DateTime.UtcNow.ToString()));
                tokens.SetNamedValue("expiry_utc", JsonValue.CreateStringValue(expiry.ToString()));
            }
            GoogleAuthJSON = tokens.ToString();
            return true;
        }

        private bool createCredential()
        {
            try
            {
                JsonObject tokens = JsonObject.Parse(GoogleAuthJSON);
                TokenResponse tokenParameter = new TokenResponse
                {
                    RefreshToken = tokens.GetNamedString("refresh_token"),
                    TokenType = tokens.GetNamedString("token_type"),
                    ExpiresInSeconds = (long)tokens.GetNamedNumber("expires_in"),
                    AccessToken = tokens.GetNamedString("access_token"),
                    IssuedUtc = DateTime.Parse(tokens.GetNamedString("issued_utc"))
                };

                ClientSecrets secrets = new ClientSecrets()
                {
                    ClientId = clientID,
                    ClientSecret = clientSecret
                };
                userCredential = new UserCredential(new GoogleAuthorizationCodeFlow(
                    new GoogleAuthorizationCodeFlow.Initializer
                    {
                        ClientSecrets = secrets
                    }),
                    "user",
                    tokenParameter);
                return true;
            }
            catch(Exception e)
            {
                Debug.WriteLine(e.Message);
                return false;
            }
            
        }

        public bool CreateService()
        {
            try
            {
                driveService = new DriveService(new BaseClientService.Initializer()
                {
                    HttpClientInitializer = userCredential,
                    ApplicationName = ApplicationName,
                });
                return true;
            }
            catch (Exception e)
            {
                Debug.WriteLine("Error creating Google Drive Service : " + e.Message);
                return false;
            }
        }
        public bool SearchFile(String fileName)
        {
            FilesResource.ListRequest listRequest = driveService.Files.List();
            listRequest.Q = "name = '" + fileName + "' and trashed = false and mimeType = 'text/plain'";
            listRequest.Fields = "files(id, name, trashed, mimeType)";

            // List files.
            IList<Google.Apis.Drive.v3.Data.File> files = listRequest.Execute().Files;
            if (files != null && files.Count > 0)
            {
                driveFile = files[0];
                return true;
            }
            else
            {
                Debug.WriteLine("No files found in Google Drive matching the filter : " + listRequest.Q.ToString());
                return false;
            }
        }
        public bool CreateFile(String fileName, String data)
        {
            try
            {
                driveService.Files.Create(new Google.Apis.Drive.v3.Data.File
                {
                    Name = fileName,
                    MimeType = "text/plain"
                }, GenerateStreamFromString(data), "text/plain").Upload();
                return true;
            }catch (Exception e)
            {
                Debug.WriteLine("Error creating file : " + e.Message);
                return false;
            }
        }

        public bool ReadFile(String fileName)
        {
            try
            {
                if (SearchFile(fileName))
                {
                    MemoryStream stream = new MemoryStream();
                    FilesResource.GetRequest getRequest = driveService.Files.Get(driveFile.Id);
                    getRequest.Download(stream);
                    stream.Position = 0;
                    StreamReader reader = new StreamReader(stream);
                    fileData = reader.ReadToEnd();
                    fileData = removeNewLineCharacters(fileData);
                }
                else
                {
                    Debug.WriteLine("Error searching for file");
                    return false;
                }
                return true;
            }catch (Exception e)
            {
                Debug.WriteLine("Error ... " + e.Message);
                return false;
            }
        }

        public bool WriteFile(String fileName, String data)
        {
            try
            {
                if (CreateService())
                {
                    
                    if (SearchFile(fileName))
                    {
                        Google.Apis.Upload.IUploadProgress uploadProgress = driveService.Files.Update(new Google.Apis.Drive.v3.Data.File
                            {
                                Name = fileName,
                                MimeType = "text/plain"
                            }, driveFile.Id, GenerateStreamFromString(data), "text/plain").Upload();
                        Google.Apis.Upload.UploadStatus status = uploadProgress.Status;
                        
                        if (status == Google.Apis.Upload.UploadStatus.Completed)
                        {
                            return true;
                        }
                        else
                        {
                            switch (status)
                            {
                                case Google.Apis.Upload.UploadStatus.Completed:
                                    return true;
                                case Google.Apis.Upload.UploadStatus.Failed:
                                    Debug.WriteLine("Error uploading content : "+ uploadProgress.Exception.Message);
                                    return false;
                                default:
                                    Debug.WriteLine(status);
                                    return false;

                            }
                        }
                        
                    }
                    else
                    {
                        return CreateFile(fileName,data);
                    }
                }
                else
                {
                    Debug.WriteLine("Error creating Google Drive Service");
                    return false;
                }
            }catch (Exception e)
            {
                Debug.WriteLine("Error in writing file : " + e.Message);
                return false;
            }
        }

        private Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
        private String removeNewLineCharacters(String sourceData)
        {
            sourceData = sourceData.Replace("\r\n", "");
            sourceData = sourceData.Replace("\r", "");
            sourceData = sourceData.Replace("\n", "");
            return sourceData;
        }

        private String updateNewLineCharacters(String sourceData)
        {
            if (sourceData != null)
            {
                sourceData = sourceData.Replace("\r\n", "\n");
                sourceData = sourceData.Replace("\n", "\r\n");
            }
            return sourceData;
        }
        
        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string randomDataBase64url(uint length)
        {
            IBuffer buffer = CryptographicBuffer.GenerateRandom(length);
            return base64urlencodeNoPadding(buffer);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static IBuffer sha256(string inputStirng)
        {
            HashAlgorithmProvider sha = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            IBuffer buff = CryptographicBuffer.ConvertStringToBinary(inputStirng, BinaryStringEncoding.Utf8);
            return sha.HashData(buff);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(IBuffer buffer)
        {
            string base64 = CryptographicBuffer.EncodeToBase64String(buffer);
            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");
            return base64;
        }
    }
}
