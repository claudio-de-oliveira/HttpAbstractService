using IdentityModel.Client;

using Microsoft.AspNetCore.JsonPatch;

using Newtonsoft.Json;

using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace ClaLuLaNa
{
    public class HttpAbstractService
    {
        protected readonly string _requestUri;
        protected readonly HttpClient _httpClient;
        private readonly JsonConverter? _jsonConverter;
        private HttpResponseMessage? _responseMessage;

        /// <summary>
        /// HttpService base class from HttpClient bypassing the SSH certificate
        /// </summary>
        /// <param name="baseUri">Base address</param>
        /// <param name="jsonConverter">Optative JSON converter</param>
        protected HttpAbstractService(string baseUri, JsonConverter? jsonConverter = null)
        {
            _requestUri = baseUri;
            _httpClient = new HttpClient(new HttpClientHandler
            {
                // Bypass the SSH certificate
                ServerCertificateCustomValidationCallback =
                       (sender, cert, chain, sslPolicyErrors) => { return true; }
            })
            {
                BaseAddress = new Uri(_requestUri)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "BlazorServer");
            _jsonConverter = jsonConverter;
        }

        /// <summary>
        /// HttpService base class from HttpClient defined by user
        /// </summary>
        /// <param name="baseUri">Base address</param>
        /// <param name="httpClient">User defined http client</param>
        /// <param name="jsonConverter">Optative JSON converter</param>
        protected HttpAbstractService(string baseUri, HttpClient httpClient, JsonConverter? jsonConverter = null)
        {
            _requestUri = baseUri;
            _httpClient = httpClient;
            _httpClient.BaseAddress = new Uri(_requestUri);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "BlazorServer");
            _jsonConverter = jsonConverter;
        }

        /// <summary>
        /// HttpService base class from HttpClient with SSH certificate
        /// </summary>
        /// <param name="baseUri">Base address</param>
        /// <param name="certificateFile">Certificate file (.pfx)</param>
        /// <param name="certificatePassword">Certificate password</param>
        /// <param name="jsonConverter">Optative JSON converter</param>
        protected HttpAbstractService(string baseUri, string certificateFile, string certificatePassword, JsonConverter jsonConverter = null!)
        {
            _requestUri = baseUri;
            _httpClient = CreateHttpClient(certificateFile, certificatePassword);
            _httpClient.BaseAddress = new Uri(_requestUri);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "BlazorServer");
            _jsonConverter = jsonConverter;
        }

        protected virtual async Task<string> GetAccessToken()
        {
            await Task.CompletedTask;
            return string.Empty;
        }

        public HttpResponseMessage? GetHttpResponseMessage()
            => _responseMessage;

        protected async Task<HttpResponseMessage> SendAsync(HttpRequestMessage requestMessage)
        {
            try
            {
                string accessToken = await GetAccessToken();

                if (!string.IsNullOrWhiteSpace(accessToken))
                    _httpClient.SetBearerToken(accessToken);

                _responseMessage = await _httpClient.SendAsync(requestMessage);
            }
            catch (Exception ex)
            {
                _responseMessage = new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.InternalServerError,
                    Content = new StringContent(ex.Message)
                };
            }

            return _responseMessage;

        }
        protected string GetUri(params object?[] keys)
        {
            string uri = _requestUri;

            for (int p = 0; p < keys.Length; p++)
                if (keys[p] is not null)
                    uri += keys[p]!.ToString() + "/";
            return uri;
        }

        protected async Task<bool> Exist(params object[] keys)
        {
            string uri = GetUri(keys);

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, uri);

            var response = await SendAsync(requestMessage);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return (_jsonConverter is null)
                    ? await Task.FromResult(JsonConvert.DeserializeObject<bool>(responseBody))
                    : await Task.FromResult(JsonConvert.DeserializeObject<bool>(responseBody, _jsonConverter));
            }

            return false;
        }

        protected async Task<int> Count(params object[] keys)
        {
            string uri = GetUri(keys);

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, uri);

            var response = await SendAsync(requestMessage);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return (_jsonConverter is null)
                    ? await Task.FromResult(JsonConvert.DeserializeObject<int>(responseBody))
                    : await Task.FromResult(JsonConvert.DeserializeObject<int>(responseBody, _jsonConverter));
            }

            return -1;
        }

        protected async Task<List<T>?> GetMany<T>(params object[] keys) where T : class
        {
            string uri = GetUri(keys);

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, uri);

            var response = await SendAsync(requestMessage);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return (_jsonConverter is null)
                    ? await Task.FromResult(JsonConvert.DeserializeObject<List<T>>(responseBody))
                    : await Task.FromResult(JsonConvert.DeserializeObject<List<T>>(responseBody, _jsonConverter));
            }

            return null;
        }

        protected async Task<T?> GetOne<T>(params object[] keys) where T : class
        {
            string uri = GetUri(keys);

            var requestMessage = new HttpRequestMessage(HttpMethod.Get, uri);

            var response = await SendAsync(requestMessage);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return (_jsonConverter is null)
                    ? await Task.FromResult(JsonConvert.DeserializeObject<T>(responseBody))
                    : await Task.FromResult(JsonConvert.DeserializeObject<T>(responseBody, _jsonConverter));
            }

            return null;
        }

        protected async Task<HttpResponseMessage> Create<T>(T obj, params object[] keys) where T : class
        {
            string uri = GetUri(keys);

            string serializedData = (_jsonConverter is null)
                ? JsonConvert.SerializeObject(obj)
                : JsonConvert.SerializeObject(obj, _jsonConverter);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(serializedData)
            };

            requestMessage.Content.Headers.ContentType
                = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            return await SendAsync(requestMessage);
        }

        protected async Task<HttpResponseMessage> Update<T>(T obj, params object[] keys) where T : class
        {
            string uri = GetUri(keys);

            string serializedData = (_jsonConverter is null)
                ? JsonConvert.SerializeObject(obj)
                : JsonConvert.SerializeObject(obj, _jsonConverter);

            var requestMessage = new HttpRequestMessage(HttpMethod.Put, uri)
            {
                Content = new StringContent(serializedData)
            };

            requestMessage.Content.Headers.ContentType
                = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await SendAsync(requestMessage);

            return await Task.FromResult(response);
        }

        protected async Task<HttpResponseMessage> Patch<T>(JsonPatchDocument<T> patchDoc, params object[] keys) where T : class
        {
            string uri = GetUri(keys);

            string serializedData = (_jsonConverter is null)
                ? JsonConvert.SerializeObject(patchDoc)
                : JsonConvert.SerializeObject(patchDoc, _jsonConverter);

            var requestMessage = new HttpRequestMessage(HttpMethod.Patch, uri)
            {
                Content = new StringContent(serializedData/*, Encoding.Unicode*/)
            };

            requestMessage.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

            var response = await SendAsync(requestMessage);

            return await Task.FromResult(response);
        }

        protected async Task<HttpResponseMessage> Delete(params object[] keys)
        {
            string uri = GetUri(keys);

            var requestMessage = new HttpRequestMessage(HttpMethod.Delete, uri);

            var response = await SendAsync(requestMessage);

            return await Task.FromResult(response);
        }

        /// <summary>
        /// ServerCertificateCustomValidation allows the client to inspect the certificate provided by the server and decide whether the client considers the certificate valid or not
        /// </summary>
        /// <returns>True for valid certificate</returns>
        protected virtual bool ServerCertificateCustomValidation(HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslErrors)
        {
            Console.WriteLine("-------------------------------------------------------------------------------");
            Console.WriteLine($"Requested URI: {requestMessage.RequestUri}");
            Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            Console.WriteLine($"Issuer: {certificate.Issuer}");
            Console.WriteLine($"Subject: {certificate.Subject}");
            Console.WriteLine($"Errors: {sslErrors}\n");

            return sslErrors == SslPolicyErrors.None;
        }

        private HttpClient CreateHttpClient(string fileName, string password)
        {
            var handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                SslProtocols = SslProtocols.Tls12,
                ServerCertificateCustomValidationCallback =
                (HttpRequestMessage message,
                    X509Certificate2? certificate,
                    X509Chain? chain,
                    SslPolicyErrors sslPolicyErrors) =>
                {
                    return ServerCertificateCustomValidation(message, certificate!, chain!, sslPolicyErrors);
                }
            };

            handler.ClientCertificates.Add(new X509Certificate2(fileName, password));

            return new HttpClient(handler);
        }

        ~HttpAbstractService()
        {
            _httpClient.DeleteAsync(_requestUri);
        }
    }
}