# ?? USDT TRC20 Transfer Tool ??

![.NET 9.0](https://img.shields.io/badge/.NET-9.0-512BD4)
![C# Version](https://img.shields.io/badge/C%23-13.0-239120)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A robust and feature-rich .NET application for interacting with USDT tokens on the TRON blockchain. This tool simplifies the process of transferring USDT tokens, checking balances, and performing various TRON address operations.

> "Because managing your digital assets shouldn't require a Ph.D. in Cryptography!" ??

## ?? Features

- ? **USDT Transfers on TRON Network**
  - MainNet transfer support
  - TestNet (Shasta) transfer support
  - Smart network selection
  
- ?? **Wallet Operations**
  - TRC20 address validation from private keys
  - TRX balance checking
  - USDT balance checking
  - Comprehensive address verification
  
- ?? **Security Features**
  - Private key masking during input
  - Local transaction signing
  - No keys stored on disk
  
- ?? **Testing Utilities**
  - Signature testing tools
  - Address verification tools
  - Base58 conversion test suite
  - Base58 character validation
  
- ?? **Error Handling**
  - Balance pre-validation before transfers
  - Comprehensive error reporting
  - Transaction verification

## ??? Architecture
???????????????????????????
?  USDT TRC20 Transfer    ?
?  Console Application    ?
???????????????????????????
            ?
???????????????????????????           ???????????????????????
?  Core Transfer Logic    ??????????????  Configuration     ?
???????????????????????????           ???????????????????????
            ?
???????????????????????????           ???????????????????????
?  Crypto Utilities       ??????????????  Address Verifier  ?
?  - TronSignature        ?           ???????????????????????
?  - TronBase58Converter  ?
???????????????????????????
            ?
???????????????????????????           ???????????????????????
?  API Communication      ??????????????  Balance Checking  ?
???????????????????????????           ???????????????????????
            ?
            ?
???????????????????????????
?  TRON Blockchain        ?
?  (MainNet/TestNet)      ?
???????????????????????????
## ?? Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) or later
- Access to the internet (for blockchain API communication)
- Basic understanding of TRON and USDT operations

## ??? Installation

1. Clone the repository:git clone https://github.com/yourusername/USDT-TRC20Transfer.git
2. Navigate to the project directory:cd USDT-TRC20Transfer
3. Build the project:dotnet build
4. Run the application:dotnet run
## ?? Configuration

The application uses `appsettings.json` for configuration. Here's a sample configuration file:
{
  "ApiEndpoints": {
    "TronGrid": {
      "Mainnet": "https://api.trongrid.io",
      "Testnet": "https://api.shasta.trongrid.io"
    }
  },
  "ExplorerUrls": {
    "Mainnet": "https://tronscan.org/#/transaction/",
    "Testnet": "https://shasta.tronscan.org/#/transaction/"
  },
  "Contracts": {
    "USDT": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
  },
  "DefaultWallet": "Your_Default_Wallet_Address",
  "TransferSettings": {
    "MinTransferAmountSun": "1",
    "MaxTransferAmountSun": "1000000000000",
    "QuickCheckAttempts": "3",
    "QuickCheckWaitMs": "5000",
    "SunToTrx": "1000000"
  }
}
## ?? Usage

### ??? Main Menu

When you run the application, you'll be presented with a menu:
?? TRON (TRX/TRC20) Operation Menu ??
===================================
1 - TRC20 Address Verification from Private Key
2 - TRX Balance Check
3 - USDT (TRC20) Balance Check
4 - Real USDT (TRC20) Transfer (MainNet)
5 - Test USDT (TRC20) Transfer (TestNet)
6 - USDT (TRC20) Network-Selectable Transfer
7 - Run Test Functions
8 - TRON Address Conversion Test (Comprehensive)
9 - Settings and Information
0 - Exit
===================================
### ?? Checking Balances

To check a TRX or USDT balance:
1. Select option 2 or 3 from the main menu
2. Enter the wallet address or leave blank to use the default address
3. View the balance information

Example output:?? USDT (TRC20) Balance: 1,234.56 USDT
   Used address: TWiWt5SEDzaEqS6kE5gandWMNfxR2B5xzg
### ?? Making a Transfer

To transfer USDT tokens:
1. Select option 4, 5, or 6 depending on your network preference
2. Enter your private key (don't worry, it's masked!)
3. Enter the recipient's address
4. Specify the amount to transfer
5. Confirm the transaction details
6. View the transaction result

Example flow:?? USDT (TRC20) Transfer - MAINNET
----------------------------------
Sender (From) private key: ********
Recipient (To) address: TRzJDfBTkbXLinWAMgMpabXJi6kP6vQPTt
Transfer amount (USDT): 50

?? Transfer Details:
Sender: TWiWt5SEDzaEqS6kE5gandWMNfxR2B5xzg
Recipient: TRzJDfBTkbXLinWAMgMpabXJi6kP6vQPTt
Amount: 50.00 USDT
Network: MAINNET

Confirm? (Y/N): Y

? Transfer completed successfully!
Transaction ID (TxID): 4a0db35c734cb8c4ea63f47fd13104af02c8ea1051a0e4772bffc131f631c944
Transaction details: https://tronscan.org/#/transaction/4a0db35c734cb8c4ea63f47fd13104af02c8ea1051a0e4772bffc131f631c944
### ?? Testing Functions

For developers and troubleshooting, various testing functions are available:
1. Select option 7 from the main menu
2. Choose from various testing options like signature testing, address verification, etc.

## ?? Security Warnings

- ?? **NEVER share your private key** with anyone
- ??? Always double-check recipient addresses before confirming transfers
- ?? Use TestNet for experimentation before using real funds on MainNet
- ?? Consider running this tool only on secure, personal computers
- ?? The tool does not store your private keys, but be cautious about keystroke loggers or screen capture malware

## ?? Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "SIGERROR" during transfer | Verify your private key matches the sender address |
| "Invalid base58 character" | Check for confusing characters (0/O, l/1/I) |
| Balance check fails | Ensure proper network connectivity and API access |
| Low TRX balance warning | Ensure you have at least 5 TRX for gas fees |
| Transaction pending | Wait for blockchain confirmation (usually 1-3 minutes) |

## ?? Advanced Features

### Base58 Character Validation

This tool includes special validation for Base58 characters to prevent common errors like confusing:
- The number `0` with the letter `O`
- The letter `l` with the number `1`
- The letter `I` with the number `1`

### Transaction Signing

Transactions are signed locally before being broadcast to the network, ensuring your private keys never leave your machine. The signing process follows these steps:

1. Create transaction parameters (sender, receiver, amount)
2. Get raw transaction from TRON API
3. Hash the transaction data with SHA-256
4. Sign hash with private key (using Nethereum.Signer)
5. Verify signature matches sender address
6. Broadcast signed transaction to the network
7. Verify transaction status

## ?? Transaction Flow
???????????????       ???????????????        ?????????????????
? User Input  ?????????Balance Check??????????Build Transaction?
???????????????       ???????????????        ???????????????????
                                                     ?
                                                     ?
???????????????       ???????????????        ?????????????????
?Show Results ?????????Verify Status??????????Sign & Broadcast?
???????????????       ???????????????        ?????????????????
## ?? Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ?? License

This project is licensed under the MIT License - see the LICENSE file for details.

## ?? Contact

Have questions? Found a bug? Want to contribute? Create an issue in this repository.

---

*Remember: With great crypto power comes great crypto responsibility!* ?????

*This tool is provided as-is with no guarantees. Always double-check transfers and use at your own risk.*