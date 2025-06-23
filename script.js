const bip39 = require('bip39');
const nacl = require('tweetnacl');
const { derivePath } = require('ed25519-hd-key');
const bs58 = require('bs58');

export class HDWallet {
    static walletCount = 0;

    constructor(mnemonic = null) {
        if (mnemonic) {
            if (!bip39.validateMnemonic(mnemonic)) {
                console.error("Invalid mnemonic.");
                process.exit(1);
            }
            this.mnemonic = mnemonic;
        } else {
            this.mnemonic = bip39.generateMnemonic();
            console.log("Generated Mnemonic:", this.mnemonic);
        }

        this.seed = bip39.mnemonicToSeedSync(this.mnemonic);
        this.wallets = [];
    }

    generateKeyPair() {
        const derivationPath = `m/44'/501'/${HDWallet.walletCount}'/0'`;
        const derivedSeed = derivePath(derivationPath, this.seed.toString('hex')).key;
        const keypair = nacl.sign.keyPair.fromSeed(derivedSeed);

        const wallet = {
            publicKey: keypair.publicKey,
            privateKey: keypair.secretKey
        };

        this.wallets.push(wallet);
        HDWallet.walletCount++;

        console.log(`Wallet #${HDWallet.walletCount} Generated`);
        console.log("Public Key (Base58):", bs58.encode(wallet.publicKey));
        console.log("Private Key (Base58):", bs58.encode(wallet.privateKey));
    }

    listWallets() {
        this.wallets.forEach((wallet, index) => {
            console.log(`--- Wallet #${index + 1} ---`);
            console.log("Public Key :", bs58.encode(wallet.publicKey));
            console.log("Private Key:", bs58.encode(wallet.privateKey));
        });
    }

    signMessage(index, message) {
        const wallet = this.wallets[index];
        if (!wallet) {
            console.error("Wallet not found.");
            return;
        }

        const messageBytes = new TextEncoder().encode(message);
        const signature = nacl.sign.detached(messageBytes, wallet.privateKey);
        console.log("Signed Message");
        console.log("Signature (Base58):", bs58.encode(signature));
        return { messageBytes, signature };
    }

    verifyMessage(index, messageBytes, signature) {
        const wallet = this.wallets[index];
        if (!wallet) {
            console.error("Wallet not found.");
            return false;
        }

        const isValid = nacl.sign.detached.verify(messageBytes, signature, wallet.publicKey);
        console.log("Signature Valid?", isValid);
        return isValid;
    }
}


