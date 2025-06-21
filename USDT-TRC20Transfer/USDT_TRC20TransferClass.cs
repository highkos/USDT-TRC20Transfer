using Microsoft.Extensions.Configuration;
using Nethereum.Signer;
using Nethereum.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SimpleBase;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace USDT_TRC20Transfer
{
    public class USDT_TRC20TransferClass
    {
        private static readonly HttpClient httpClient = new HttpClient();
        private static IConfiguration ProgramConfiguration => TRX_TRC20Transfer.Program.Configuration;

        /// <summary>
        /// Runs a production USDT TRC20 transfer with user input for parameters
        /// </summary>
        public static async Task RunProductionTransfer()
        {
            Console.WriteLine("\n--- GÜVENLİ USDT (TRC20) TRANSFERİ ---");

            // Select network (Mainnet or Testnet)
            bool isMainnet = SelectNetwork();

            // Secure private key input
            SecureString securePrivateKey = GetSecurePrivateKey();

            // Get sender address from private key
            string senderAddress = GetAddressFromSecurePrivateKey(securePrivateKey);

            // Confirm sender address
            if (!ConfirmSenderAddress(senderAddress))
            {
                Console.WriteLine("Transfer iptal edildi.");
                return;
            }

            // Get and validate receiver address
            string receiverAddress = GetValidatedReceiverAddress();

            // Get and validate transfer amount
            decimal usdtAmount = GetValidatedUsdtAmount();

            // Basic balance check
            await PerformBasicChecks(senderAddress, usdtAmount, isMainnet);

            // Final confirmation
            if (!GetFinalUsdtConfirmation(senderAddress, receiverAddress, usdtAmount, isMainnet))
            {
                Console.WriteLine("Transfer iptal edildi.");
                return;
            }

            // Execute transfer
            await ExecuteSecureUsdtTransfer(securePrivateKey, receiverAddress, usdtAmount, isMainnet);
        }

        /// <summary>
        /// Runs a MainNet USDT TRC20 transfer with user input for parameters but automatically selects MainNet
        /// </summary>
        public static async Task RunMainNetTransfer()
        {
            Console.WriteLine("\n--- GERÇEK USDT (TRC20) TRANSFERİ (MAINNET) ---");

            // Automatically use MainNet
            bool isMainnet = true;

            // Secure private key input
            SecureString securePrivateKey = GetSecurePrivateKey();

            // Get sender address from private key
            string senderAddress = GetAddressFromSecurePrivateKey(securePrivateKey);

            // Confirm sender address
            if (!ConfirmSenderAddress(senderAddress))
            {
                Console.WriteLine("Transfer iptal edildi.");
                return;
            }

            // Get and validate receiver address
            string receiverAddress = GetValidatedReceiverAddress();

            // Get and validate transfer amount
            decimal usdtAmount = GetValidatedUsdtAmount();

            // Basic balance check
            await PerformBasicChecks(senderAddress, usdtAmount, isMainnet);

            // Final confirmation
            if (!GetFinalUsdtConfirmation(senderAddress, receiverAddress, usdtAmount, isMainnet))
            {
                Console.WriteLine("Transfer iptal edildi.");
                return;
            }

            // Execute transfer
            await ExecuteSecureUsdtTransfer(securePrivateKey, receiverAddress, usdtAmount, isMainnet);
        }

        /// <summary>
        /// Runs a TestNet USDT TRC20 transfer with user input for parameters but automatically selects TestNet
        /// </summary>
        public static async Task RunTestNetTransfer()
        {
            Console.WriteLine("\n--- TEST USDT (TRC20) TRANSFERİ (TESTNET) ---");

            // Automatically use TestNet
            bool isMainnet = false;

            // Secure private key input
            SecureString securePrivateKey = GetSecurePrivateKey();

            // Get sender address from private key
            string senderAddress = GetAddressFromSecurePrivateKey(securePrivateKey);

            // Confirm sender address
            if (!ConfirmSenderAddress(senderAddress))
            {
                Console.WriteLine("Transfer iptal edildi.");
                return;
            }

            // Get and validate receiver address
            string receiverAddress = GetValidatedReceiverAddress();

            // Get and validate transfer amount
            decimal usdtAmount = GetValidatedUsdtAmount();

            // Basic balance check
            await PerformBasicChecks(senderAddress, usdtAmount, isMainnet);

            // Final confirmation
            if (!GetFinalUsdtConfirmation(senderAddress, receiverAddress, usdtAmount, isMainnet))
            {
                Console.WriteLine("Transfer iptal edildi.");
                return;
            }

            // Execute transfer
            await ExecuteSecureUsdtTransfer(securePrivateKey, receiverAddress, usdtAmount, isMainnet);
        }

        private static bool SelectNetwork()
        {
            Console.WriteLine("\nAğ Seçimi:");
            Console.WriteLine("1. MainNet (Gerçek USDT)");
            Console.WriteLine("2. Shasta TestNet (Test USDT)");
            Console.Write("Seçiminiz (1-2): ");

            string choice = Console.ReadLine() ?? "";
            return choice == "1";
        }

        private static SecureString GetSecurePrivateKey()
        {
            Console.WriteLine("\nPrivate Key Girişi:");
            Console.WriteLine("UYARI: Private key'inizi kimseyle paylaşmayın!");
            Console.Write("Private Key (gizli): ");

            SecureString secureString = new SecureString();
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    secureString.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && secureString.Length > 0)
                {
                    secureString.RemoveAt(secureString.Length - 1);
                    Console.Write("\b \b");
                }
            }
            while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            secureString.MakeReadOnly();

            if (secureString.Length == 0)
            {
                throw new ArgumentException("Private key boş olamaz!");
            }

            return secureString;
        }

        private static bool ConfirmSenderAddress(string senderAddress)
        {
            Console.WriteLine("\n--- GÖNDERİCİ ADRESİ ONAY ---");
            Console.WriteLine($"Private key'inizden türetilen adres: {senderAddress}");
            Console.Write("Bu adresten transfer yapmak istiyor musunuz? (E/H) :  ");

            string response = Console.ReadLine()?.ToUpper() ?? "";
            return response == "E";
        }

        private static string GetValidatedReceiverAddress()
        {
            Console.Write("\nAlıcı TRON Adresi: ");
            string address = Console.ReadLine()?.Trim() ?? "";

            if (!IsValidTronAddress(address))
            {
                throw new ArgumentException("Geçersiz TRON adresi!");
            }

            return address;
        }

        private static decimal GetValidatedUsdtAmount()
        {
            Console.Write("Transfer Miktarı (USDT): ");
            if (!decimal.TryParse(Console.ReadLine(), out decimal amount) || amount <= 0)
            {
                throw new ArgumentException("Geçersiz USDT miktarı!");
            }

            // USDT has 6 decimals (1 USDT = 1,000,000 Token Units)
            if (amount < 0.000001m)
            {
                throw new ArgumentException("Minimum transfer miktarı: 0.000001 USDT");
            }

            if (amount > 1_000_000m) // Example max amount, adjust as needed
            {
                throw new ArgumentException("Maksimum transfer miktarı: 1,000,000 USDT");
            }

            return amount;
        }

        private static string GetAddressFromSecurePrivateKey(SecureString securePrivateKey)
        {
            string privateKeyStr = SecureStringToString(securePrivateKey);
            try
            {
                // Private key validation
                if (privateKeyStr.Length != 64 || !IsHexString(privateKeyStr))
                {
                    throw new ArgumentException("Geçersiz private key formatı!");
                }

                // Generate address using TronAddressVerifier
                var result = TronAddressVerifier.GenerateAndVerifyTronAddress(privateKeyStr);
                return result.GeneratedAddress;
            }
            finally
            {
                // Securely clear the private key from memory
                ClearString(ref privateKeyStr);
            }
        }

        private static async Task PerformBasicChecks(string senderAddress, decimal usdtAmount, bool isMainnet)
        {
            Console.WriteLine("\n--- BAKIYE KONTROLÜ ---");

            try
            {
                // Check USDT balance
                var usdtBalanceService = new USDT_TRC20AccountBalance();
                usdtBalanceService.WalletAddress = senderAddress;
                decimal usdtBalance = await usdtBalanceService.GetUsdtBalance();
                Console.WriteLine($"USDT Bakiyeniz: {usdtBalance:N6} USDT");

                if (usdtBalance < usdtAmount)
                {
                    throw new InvalidOperationException("Yetersiz USDT bakiyesi!");
                }

                // Check TRX balance for network fee
                var trxBalanceService = new TRX_TRC20AccountBalance();
                trxBalanceService.WalletAddress = senderAddress;
                decimal trxBalance = await trxBalanceService.GetTrxBalance();
                Console.WriteLine($"TRX Bakiyeniz: {trxBalance:N6} TRX ({(long)(trxBalance * Configuration.SUN_TO_TRX)} SUN)");

                // For TRC20 transfers, approximately 5-15 TRX might be needed for energy
                decimal estimatedTrxFee = 10m; // Conservative estimate for TRC20 transfer
                Console.WriteLine($"Tahmini işlem ücreti: ~{estimatedTrxFee} TRX");

                if (trxBalance < estimatedTrxFee)
                {
                    throw new InvalidOperationException($"İşlem ücreti için yetersiz TRX! En az {estimatedTrxFee} TRX gerekli.");
                }
            }
            catch (Exception ex)
            {
                LogError($"Bakiye kontrolü hatası: {ex.Message}");
                throw;
            }
        }

        private static bool GetFinalUsdtConfirmation(string senderAddress, string receiverAddress, decimal usdtAmount, bool isMainnet)
        {
            Console.WriteLine("\n--- TRANSFER ONAY ---");
            Console.WriteLine($"Token: USDT (TRC20)");
            Console.WriteLine($"Gönderici: {senderAddress}");
            Console.WriteLine($"Alıcı: {receiverAddress}");
            Console.WriteLine($"Miktar: {usdtAmount:N6} USDT");
            Console.WriteLine($"Ağ: {(isMainnet ? "MainNet (GERÇEK)" : "Shasta TestNet")}");
            Console.WriteLine("\nBU İŞLEM GERİ ALINAMAZ!");
            Console.Write("Transfer'i onaylıyor musunuz? 'E/H' : ");

            return Console.ReadLine()?.ToUpper() == "E";
        }

        private static async Task ExecuteSecureUsdtTransfer(SecureString securePrivateKey, string receiverAddress, decimal usdtAmount, bool isMainnet)
        {
            string? transactionId = null;

            try
            {
                Console.WriteLine("\n--- TRANSFER İŞLEMİ ---");
                Console.WriteLine("USDT Transfer işlemi başlatılıyor...");

                // Get contract address from configuration
                string usdtContractAddress = ProgramConfiguration?["Contracts:USDT"] ?? "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

                // Convert USDT amount to token units (USDT has 6 decimals)
                BigInteger tokenAmount = new BigInteger(usdtAmount * 1_000_000m);

                // Create and broadcast TRC20 token transaction
                transactionId = await CreateAndBroadcastTrc20Transaction(
                    securePrivateKey,
                    receiverAddress,
                    usdtContractAddress,
                    tokenAmount,
                    isMainnet
                );

                Console.WriteLine($"✅ USDT Transaction başarıyla gönderildi!");
                Console.WriteLine($"Transaction ID: {transactionId}");

                // Generate tracking link
                string explorerUrl = isMainnet ? Configuration.MAINNET_EXPLORER : Configuration.TESTNET_EXPLORER;
                string trackingLink = explorerUrl + transactionId;

                Console.WriteLine($"\n📄 İşlemi takip etmek için:");
                Console.WriteLine($"🔗 {trackingLink}");

                // Quick confirmation check (non-blocking)
                Console.WriteLine("\nHızlı onay kontrolü yapılıyor...");
                bool isQuickConfirmed = await QuickConfirmationCheck(transactionId, isMainnet);

                if (isQuickConfirmed)
                {
                    Console.WriteLine("🎉 USDT Transfer onaylandı ve başarıyla tamamlandı!");
                    LogUsdtTransaction(transactionId, receiverAddress, usdtAmount, isMainnet, "CONFIRMED");
                }
                else
                {
                    Console.WriteLine("⏳ USDT Transfer gönderildi, onay için yukarıdaki linki takip edin.");
                    LogUsdtTransaction(transactionId, receiverAddress, usdtAmount, isMainnet, "SENT");
                }
            }
            catch (Exception ex)
            {
                LogError($"USDT Transfer hatası: {ex.Message}");
                if (transactionId != null)
                {
                    LogUsdtTransaction(transactionId, receiverAddress, usdtAmount, isMainnet, "FAILED");
                }
                throw;
            }
        }

        private static string SecureStringToString(SecureString value)
        {
            IntPtr valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
            try
            {
                return Marshal.PtrToStringUni(valuePtr) ?? string.Empty;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private static void ClearString(ref string str)
        {
            unsafe
            {
                if (!string.IsNullOrEmpty(str))
                {
                    fixed (char* ptr = str)
                    {
                        for (int i = 0; i < str.Length; i++)
                        {
                            ptr[i] = '\0';
                        }
                    }
                    str = string.Empty;
                }
            }
        }

        private static bool IsHexString(string input)
        {
            return input.All(c => "0123456789abcdefABCDEF".Contains(c));
        }

        private static bool IsValidTronAddress(string address)
        {
            return address.StartsWith("T") && address.Length == 34;
        }

        private static async Task<string> CreateAndBroadcastTrc20Transaction(
            SecureString securePrivateKey,
            string receiverAddress,
            string contractAddress,
            BigInteger amount,
            bool isMainnet)
        {
            string apiUrl = isMainnet ? Configuration.MAINNET_API : Configuration.TESTNET_API;
            string privateKeyStr = SecureStringToString(securePrivateKey);
            string senderAddress = GetAddressFromSecurePrivateKey(securePrivateKey);

            try
            {
                // For TRC20 tokens, we need to call the "transfer" method of the USDT token contract
                // The ABI function signature for transfer is: transfer(address,uint256)
                string methodSignature = "transfer(address,uint256)";

                // Calculate function selector (first 4 bytes of the Keccak hash of the signature)
                byte[] functionSelector;

                // Use a different approach to calculate the function selector
                var keccak256 = new Sha3Keccack();
                functionSelector = keccak256.CalculateHash(Encoding.UTF8.GetBytes(methodSignature)).Take(4).ToArray();

                // Encode parameter: address (receiverAddress without T prefix)
                string receiverAddressHex = Base58CheckToHexAddress(receiverAddress);

                // Remove T prefix if still exists and ensure it's 64 chars (32 bytes) with padding
                if (receiverAddressHex.StartsWith("41"))
                    receiverAddressHex = receiverAddressHex.Substring(2);

                receiverAddressHex = receiverAddressHex.PadLeft(64, '0');

                // Encode parameter: uint256 (amount)
                string amountHex = amount.ToString("x").PadLeft(64, '0');

                // Combine everything to create the full call data
                string callData = "0x" +
                                  BitConverter.ToString(functionSelector).Replace("-", "").ToLowerInvariant() +
                                  receiverAddressHex +
                                  amountHex;

                Console.WriteLine($"Oluşturulan callData: {callData}");

                // 1. Create TriggerSmartContract request
                var createTxRequest = new
                {
                    owner_address = senderAddress,
                    contract_address = contractAddress,
                    function_selector = "transfer(address,uint256)",
                    parameter = callData,
                    fee_limit = 100_000_000, // 100 TRX max fee limit
                    call_value = 0,
                    visible = true
                };

                // 2. Create transaction
                string createEndpoint = $"{apiUrl}/wallet/triggersmartcontract";
                string createResponse = await PostApiRequest(createEndpoint, createTxRequest);
                var txData = JsonConvert.DeserializeObject<JObject>(createResponse);

                if (txData == null)
                    throw new Exception("Transaction oluşturma hatası: Boş yanıt alındı");

                if (txData["result"]?.Value<bool>() != true)
                    throw new Exception($"Transaction oluşturma hatası: {txData["message"] ?? "Bilinmeyen hata"}");

                // Extract transaction from response
                var transaction = txData["transaction"]?.ToObject<JObject>();
                if (transaction == null)
                    throw new Exception("Transaction verisi alınamadı");

                string? txId = transaction["txID"]?.ToString();
                if (string.IsNullOrEmpty(txId))
                    throw new Exception("Transaction ID alınamadı");

                // 3. Sign transaction locally - Fixed the casting issue
                var signedTx = SignTransaction(transaction, privateKeyStr);

                if (signedTx == null)
                    throw new Exception("İşlem imzalama hatası");

                // 4. Broadcast transaction
                string broadcastEndpoint = $"{apiUrl}/wallet/broadcasttransaction";
                string broadcastResponse = await PostApiRequest(broadcastEndpoint, signedTx);
                var broadcastResult = JsonConvert.DeserializeObject<JObject>(broadcastResponse);

                if (broadcastResult == null)
                    throw new Exception("Broadcast hatası: Boş yanıt alındı");

                if (broadcastResult["result"]?.Value<bool>() == true)
                {
                    return txId;
                }

                throw new Exception($"Broadcast hatası: {broadcastResult["code"] ?? broadcastResult["message"] ?? "Bilinmeyen hata"}");
            }
            finally
            {
                // Securely clear the private key from memory
                ClearString(ref privateKeyStr);
            }
        }

        // Convert TRON Base58Check address to hex address
        private static string Base58CheckToHexAddress(string address)
        {
            if (address.StartsWith("T"))
            {
                try
                {
                    byte[] decoded = Base58.Bitcoin.Decode(address);
                    // First 4 bytes are prefix (0x41 for TRON) and last 4 bytes are checksum
                    byte[] addressBytes = decoded.Take(decoded.Length - 4).ToArray();
                    return "41" + BitConverter.ToString(addressBytes.Skip(1).ToArray()).Replace("-", "").ToLowerInvariant();
                }
                catch
                {
                    throw new ArgumentException("Geçersiz TRON adresi formatı");
                }
            }
            return address;
        }

        private static async Task<bool> QuickConfirmationCheck(string transactionId, bool isMainnet)
        {
            string apiUrl = isMainnet ? Configuration.MAINNET_API : Configuration.TESTNET_API;

            for (int attempt = 1; attempt <= Configuration.QUICK_CHECK_ATTEMPTS; attempt++)
            {
                try
                {
                    await Task.Delay(Configuration.QUICK_CHECK_WAIT_MS);

                    JObject? tx = JsonConvert.DeserializeObject<JObject>(
                        await GetApiRequest($"{apiUrl}/wallet/gettransactionbyid?value={transactionId}")
                    );

                    if (tx != null && tx.Count > 0)
                    {
                        // Check if transaction is included in a block
                        if (tx["blockNumber"] != null || tx["block_timestamp"] != null)
                        {
                            return true;
                        }
                    }

                    Console.WriteLine($"Kontrol {attempt}/{Configuration.QUICK_CHECK_ATTEMPTS} - henüz onaylanmadı...");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Kontrol hatası (deneme {attempt}): {ex.Message}");
                }
            }

            return false;
        }

        private static async Task<string> PostApiRequest(string url, object data)
        {
            var json = JsonConvert.SerializeObject(data, Formatting.None);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            Console.WriteLine($"API Request to {url}");

            using HttpResponseMessage response = await httpClient.PostAsync(url, content);
            string responseContent = await response.Content.ReadAsStringAsync();

            Console.WriteLine($"API Response Status: {response.StatusCode}");

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Response Content: {responseContent}");
                throw new HttpRequestException($"API hatası: {response.StatusCode}, İçerik: {responseContent}");
            }

            return responseContent;
        }

        private static async Task<string> GetApiRequest(string url)
        {
            using HttpResponseMessage response = await httpClient.GetAsync(url);
            string responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"API hatası: {response.StatusCode}, İçerik: {responseContent}");
            }

            return responseContent;
        }

        private static void LogUsdtTransaction(string txId, string receiver, decimal amount, bool isMainnet, string status)
        {
            string explorerUrl = isMainnet ? Configuration.MAINNET_EXPLORER : Configuration.TESTNET_EXPLORER;
            string trackingLink = explorerUrl + txId;

            string logEntry = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC} | TX: {txId} | TOKEN: USDT | TO: {receiver} | AMOUNT: {amount:N6} USDT | NETWORK: {(isMainnet ? "MAINNET" : "TESTNET")} | STATUS: {status} | LINK: {trackingLink}";

            try
            {
                File.AppendAllText("usdt_transactions.log", logEntry + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Log yazma hatası: {ex.Message}");
            }
        }

        private static void LogError(string error)
        {
            string logEntry = $"{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC} | ERROR: {error}";

            try
            {
                File.AppendAllText("errors.log", logEntry + Environment.NewLine);
                Console.WriteLine($"HATA: {error}");
            }
            catch
            {
                Console.WriteLine($"KRITIK HATA: {error}");
            }
        }

        private static JObject SignTransaction(JObject transaction, string privateKeyHex)
        {
            try
            {
                string? rawDataHex = transaction["raw_data_hex"]?.ToString();
                if (string.IsNullOrEmpty(rawDataHex))
                    throw new Exception("Transaction raw_data_hex bulunamadı");

                // Create a deep clone of the transaction
                JObject signedTx = (JObject)transaction.DeepClone();

                byte[] rawDataBytes = Hex.HexToBytes(rawDataHex);

                byte[] messageHash;
                using (SHA256 sha256 = SHA256.Create())
                {
                    messageHash = sha256.ComputeHash(rawDataBytes);
                }

                var signer = new MessageSigner();
                string signatureHex = signer.Sign(messageHash, privateKeyHex);

                if (signatureHex.StartsWith("0x"))
                    signatureHex = signatureHex.Substring(2);

                JArray signatures = new JArray();
                signatures.Add(signatureHex);
                signedTx["signature"] = signatures;

                return signedTx;
            }
            catch (Exception ex)
            {
                throw new Exception($"Transaction imzalama hatası: {ex.Message}", ex);
            }
        }
    }

    // Helper class for hex operations
    public static class Hex
    {
        public static byte[] HexToBytes(string hex)
        {
            if (hex.StartsWith("0x"))
                hex = hex.Substring(2);

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        public static string ToHex(byte[] bytes, bool prefix = false)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            if (prefix)
                hex.Append("0x");

            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        public static byte[] Concat(params byte[][] arrays)
        {
            var result = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }
            return result;
        }
    }

    // Extension method to convert byte array to hex string
    public static class ByteArrayExtensions
    {
        public static string ToHexString(this byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
    }
}