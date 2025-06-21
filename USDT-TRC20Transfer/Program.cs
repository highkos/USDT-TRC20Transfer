using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.IO;
using USDT_TRC20Transfer;

namespace USDT_TRC20Transfer
{
    class Program
    {
        // Initialize with empty configuration to avoid CS8618
        public static IConfiguration Configuration { get; private set; } = new ConfigurationBuilder().Build();

        static async Task Main(string[] args)
        {
            // Set up configuration
            ConfigureServices();

            bool exitProgram = false;

            while (!exitProgram)
            {
                Console.Clear();
                Console.WriteLine("🔷 TRON (TRX/TRC20) İşlem Menüsü 🔷");
                Console.WriteLine("===================================");
                Console.WriteLine("1 - TRC20 Private Key'den Adres Doğrulama");
                Console.WriteLine("2 - TRX Bakiye Sorgulama");
                Console.WriteLine("3 - USDT (TRC20) Bakiye Sorgulama");
                Console.WriteLine("4 - Gerçek USDT (TRC20) Transferi (MainNet)");
                Console.WriteLine("5 - Test USDT (TRC20) Transferi (TestNet)");
                Console.WriteLine("6 - USDT (TRC20) Ağ Seçimli Transfer");
                Console.WriteLine("7 - Test Fonksiyonları Çalıştır");
                Console.WriteLine("0 - Çıkış");
                Console.WriteLine("===================================");
                Console.Write("Seçiminiz: ");

                string choice = Console.ReadLine()?.Trim() ?? "";

                Console.Clear();

                try
                {
                    switch (choice)
                    {
                        case "1":
                            await Task.Run(() => VerifyTronAddressFromPrivateKey());
                            break;
                        case "2":
                            await CheckTrxBalance();
                            break;
                        case "3":
                            await CheckUsdtBalance();
                            break;
                        case "4":
                            // Gerçek USDT Transferi (MainNet) - doğrudan MainNet kullanır
                            await USDT_TRC20TransferClass.RunMainNetTransfer();
                            break;
                        case "5":
                            // Test USDT Transferi (TestNet) - doğrudan TestNet kullanır
                            await USDT_TRC20TransferClass.RunTestNetTransfer();
                            break;
                        case "6":
                            // Ağ seçimli USDT transferi
                            await USDT_TRC20TransferClass.RunProductionTransfer();
                            break;
                        case "7":
                            // Test Fonksiyonları
                            await RunTestFunctions();
                            break;
                        case "0":
                            exitProgram = true;
                            Console.WriteLine("Program kapatılıyor...");
                            break;
                        default:
                            Console.WriteLine("❌ Geçersiz seçim! Lütfen tekrar deneyin.");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Hata: {ex.Message}");
                    if (ex.InnerException != null)
                    {
                        Console.WriteLine($"   Ayrıntı: {ex.InnerException.Message}");
                    }
                }

                if (!exitProgram)
                {
                    Console.WriteLine("\nAna menüye dönmek için bir tuşa basın...");
                    Console.ReadKey();
                }
            }
        }

        private static void ConfigureServices()
        {
            try
            {
                // Build configuration
                var builder = new ConfigurationBuilder();
                var basePath = Directory.GetCurrentDirectory();

                // In .NET 9, you don't need SetBasePath anymore
                builder.AddJsonFile(Path.Combine(basePath, "appsettings.json"), optional: false, reloadOnChange: true)
                       .AddEnvironmentVariables();

                Configuration = builder.Build();

                Console.WriteLine($"Configuration loaded from {Path.Combine(basePath, "appsettings.json")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading configuration: {ex.Message}");
                // Create a default configuration to prevent null references
                Configuration = new ConfigurationBuilder().Build();
            }
        }

        // TronAddressVerifier ile private key'den adres doğrulama işlemini gerçekleştirir
        private static void VerifyTronAddressFromPrivateKey()
        {
            Console.WriteLine("🔐 TRC20 Private Key'den Adres Doğrulama");
            Console.WriteLine("----------------------------------------");

            Console.Write("Private Key girin (64 karakter hex): ");
            string privateKey = Console.ReadLine()?.Trim() ?? "";

            Console.Write("Doğrulanacak adres (opsiyonel): ");
            string addressToVerify = Console.ReadLine()?.Trim() ?? "";

            var result = TronAddressVerifier.GenerateAndVerifyTronAddress(privateKey, addressToVerify);

            Console.WriteLine("\n🔹 Sonuçlar:");
            Console.WriteLine($"Public Key: {result.PublicKey}");
            Console.WriteLine($"Üretilen TRC20 Adresi: {result.GeneratedAddress}");

            if (!string.IsNullOrEmpty(addressToVerify))
            {
                Console.WriteLine($"Doğrulama Sonucu: {(result.IsMatch ? "✅ Adres eşleşiyor!" : "❌ Adres eşleşmiyor!")}");
            }
        }

        // TRX_TRCAccountBalance ile TRX bakiye sorgulama işlemini gerçekleştirir
        private static async Task CheckTrxBalance()
        {
            Console.WriteLine("💰 TRX Bakiye Sorgulama");
            Console.WriteLine("------------------------");

            string? walletAddress = PromptForWalletAddress();
            if (string.IsNullOrEmpty(walletAddress))
            {
                Console.WriteLine("Varsayılan cüzdan adresi kullanılacak.");
            }

            try
            {
                Console.WriteLine($"\nTRX bakiyesi sorgulanıyor ({(string.IsNullOrEmpty(walletAddress) ? "varsayılan adres" : walletAddress)}), lütfen bekleyin...");

                var trxBalanceService = new TRX_TRC20AccountBalance();
                if (!string.IsNullOrEmpty(walletAddress))
                {
                    trxBalanceService.WalletAddress = walletAddress;
                }
                else
                {
                    // Use default wallet from configuration
                    string? defaultWallet = Configuration["DefaultWallet"];
                    trxBalanceService.WalletAddress = defaultWallet ?? trxBalanceService.WalletAddress;
                }

                decimal balance = await trxBalanceService.GetTrxBalance();

                Console.WriteLine($"\n💲 TRX Bakiyeniz: {balance:N6} TRX");
                Console.WriteLine($"   Kullanılan adres: {trxBalanceService.WalletAddress}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ TRX bakiye sorgulaması başarısız: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"   Ayrıntı: {ex.InnerException.Message}");
                }
            }
        }

        // USDT_TRC20AccountBalance ile USDT bakiye sorgulama işlemini gerçekleştirir
        private static async Task CheckUsdtBalance()
        {
            Console.WriteLine("💵 USDT (TRC20) Bakiye Sorgulama");
            Console.WriteLine("--------------------------------");

            string? walletAddress = PromptForWalletAddress();
            if (string.IsNullOrEmpty(walletAddress))
            {
                Console.WriteLine("Varsayılan cüzdan adresi kullanılacak.");
            }

            try
            {
                Console.WriteLine($"\nUSDT bakiyesi sorgulanıyor ({(string.IsNullOrEmpty(walletAddress) ? "varsayılan adres" : walletAddress)}), lütfen bekleyin...");

                var usdtBalanceService = new USDT_TRC20AccountBalance();
                if (!string.IsNullOrEmpty(walletAddress))
                {
                    usdtBalanceService.WalletAddress = walletAddress;
                }
                else
                {
                    // Use default wallet from configuration
                    string? defaultWallet = Configuration["DefaultWallet"];
                    usdtBalanceService.WalletAddress = defaultWallet ?? usdtBalanceService.WalletAddress;
                }

                decimal balance = await usdtBalanceService.GetUsdtBalance();

                Console.WriteLine($"\n💲 USDT (TRC20) Bakiyeniz: {balance:N2} USDT");
                Console.WriteLine($"   Kullanılan adres: {usdtBalanceService.WalletAddress}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ USDT bakiye sorgulaması başarısız: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"   Ayrıntı: {ex.InnerException.Message}");
                }
            }
        }

        // Test fonksiyonları için kullanılacak demo fonksiyonları
        private static async Task RunTestFunctions()
        {
            Console.WriteLine("🧪 Test Fonksiyonları");
            Console.WriteLine("---------------------");
            Console.WriteLine("1 - Adres Doğrulama Testi");
            Console.WriteLine("2 - API Bağlantı Testi");
            Console.WriteLine("3 - Bakiye Sorgulama Testi");
            Console.WriteLine("4 - Transaction Hash Testi");
            Console.WriteLine("0 - Geri Dön");
            Console.Write("\nSeçiminiz: ");

            string choice = Console.ReadLine()?.Trim() ?? "";

            Console.WriteLine("\nTest işlemi seçildi. Bu fonksiyon henüz tam olarak uygulanmamıştır.");
            Console.WriteLine("İlgili testler daha sonraki sürümlerde eklenecektir.");

            // Add a minimal await operation to avoid CS1998 warning
            await Task.Delay(1);
            return;
        }

        // Kullanıcıdan cüzdan adresi girmesini ister ve doğrular
        private static string? PromptForWalletAddress()
        {
            Console.WriteLine("👛 Cüzdan adresinizi girin (T ile başlayan 34 karakterlik adres)");
            Console.WriteLine("   Boş bırakırsanız varsayılan adres kullanılacaktır.");
            Console.Write("➤ ");

            string address = Console.ReadLine()?.Trim() ?? "";

            if (string.IsNullOrEmpty(address))
            {
                return null;
            }

            // Basit adres kontrolü
            if (!address.StartsWith("T") || address.Length != 34)
            {
                Console.WriteLine("❌ Geçersiz TRX cüzdan adresi! Adres 'T' ile başlamalı ve 34 karakter olmalıdır.");
                Console.WriteLine("   Varsayılan adres kullanılacak.");
                return null;
            }

            return address;
        }
    }
}