# Solana HD Wallet CLI

This is a Node.js command-line application for generating and managing Solana HD (Hierarchical Deterministic) wallets using a 12-word mnemonic phrase.

## Features

- Generate a new 12-word mnemonic
- Restore a wallet from an existing mnemonic
- Derive multiple Solana keypairs from one mnemonic
- Sign a message with a selected wallet
- Verify a signed message
- View all generated public and private keys

## How It Works

1. When you run the app, a menu is shown with options:
   - Generate a new mnemonic
   - Enter an existing mnemonic
   - Generate new keypairs
   - View all keypairs
   - Sign a message
   - Verify a message
   - Exit the application

2. You can generate multiple wallets from a single mnemonic using Solana’s derivation path:

