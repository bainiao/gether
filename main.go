package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
)

func main() {
	// _, err := ethclient.Dial("https://cloudflare-eth.com")
	// client := connectServer("https://rpc.sepolia.org")
	// address := common.HexToAddress("0x959FD7Ef9089B7142B6B908Dc3A8af7Aa8ff0FA1")
	// // fmt.Println(address.Hex())
	// // fmt.Println(address)
	// // fmt.Println(address.Bytes())
	// getBalance(client, address)
	// generateWallet()
	// createKs()
	// importKs()
}

func connectServer(server string) *ethclient.Client {
	client, err := ethclient.Dial(server)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("connect to %s success.", server)
	return client
}

func getBalance(client *ethclient.Client, address common.Address) {
	balance, err := client.BalanceAt(context.Background(), address, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Balance is:", balance)
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
	fmt.Println("eth value:", ethValue)
	blockNum := big.NewInt(0)
	balanceAt, err := client.BalanceAt(context.Background(), address, blockNum)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Balance at 0:", balanceAt)
	pendingBalance, err := client.PendingBalanceAt(context.Background(), address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Pending balance:", pendingBalance)
}

func generateWallet() {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("private key:", privateKey)
	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println("private key bytes:", hexutil.Encode(privateKeyBytes[2:]))
	publicKey := privateKey.Public()
	fmt.Println("public key:", publicKey)
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: public key is not of type *ecdsa.PublicKey")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("public key:", hexutil.Encode(publicKeyBytes))
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println("address:", address)
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKeyBytes[1:])
	fmt.Println("hash pub key:", hexutil.Encode(hash.Sum(nil)[12:]))
}
func createKs() {
	ks := keystore.NewKeyStore("./tmp", keystore.StandardScryptN, keystore.StandardScryptP)
	password := "secret"
	account, err := ks.NewAccount(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(account.Address.Hex())
}
func importKs() {
	file := "./tmp/UTC--2025-11-11T00-38-17.452294200Z--552944736445f5c42c6e51be47d5e50869247498"
	ks := keystore.NewKeyStore("./tmp", keystore.StandardScryptN, keystore.StandardScryptP)
	accounts := ks.Accounts()
	for _, account := range accounts {
		fmt.Println("accout:", account.Address.Hex())
	}
	jsonBytes, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	password := "secret"
	privateKey, err := keystore.DecryptKey(jsonBytes, password)
	if err != nil {
		fmt.Printf("decrypt ks file fail: %v\n", err)
		return
	}
	fmt.Println(privateKey.PrivateKey)
	privateKeyBytes := crypto.FromECDSA(privateKey.PrivateKey)
	fmt.Println("private key:", hexutil.Encode(privateKeyBytes))
	publicKey := crypto.PubkeyToAddress(privateKey.PrivateKey.PublicKey)
	fmt.Println("address:", publicKey)
	publicKeyBytes := crypto.FromECDSAPub(&privateKey.PrivateKey.PublicKey)
	fmt.Printf("public key: 0x%xf", publicKeyBytes)
	// account, err := ks.Import(jsonBytes, password, password)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println(account.Address.Hex())
	// if err := os.Remove(file); err != nil {
	// 	log.Fatal(err)
	// }
}
func queryBlock(client *ethclient.Client) {
	// 1. block header, block(value, transactions,sender, to,gas fee,gas)
	// check client
	if client == nil {
		fmt.Println("client is nis")
		return
	}
	// get block header
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(header.Number.String())
	blockNumber := big.NewInt(111)
	// get block by block number
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(block.Hash().Hex())
	fmt.Println(len(block.Transactions()))
	// iterate over the transactions in block
	// loop through/traverse
	for _, tx := range block.Transactions() {
		fmt.Println(tx.Hash().Hex())
		fmt.Println(tx.Hash())
		fmt.Println(tx.Hash().Bytes())
		fmt.Println(tx.GasPrice().Uint64())
		fmt.Println(tx.Gas())
		fmt.Println(tx.Data())
		fmt.Println(tx.Nonce())
		fmt.Println(tx.To().Hex())
		// transaction sender
		signer := types.LatestSignerForChainID(tx.ChainId())
		from, err := signer.Sender(tx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("sender:", from.Hex())
		// receipt
		receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(receipt.Status)
	}
	transactionCount, err := client.TransactionCount(context.Background(), block.Hash())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(transactionCount)
	for i := uint(0); i < transactionCount; i++ {
		tx, err := client.TransactionInBlock(context.Background(), block.Hash(), i)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(tx.Hash().Hex())
		_, ispending, err := client.TransactionByHash(context.Background(), tx.Hash())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ispending)
	}

}
func transferEth(client *ethclient.Client) {
	if client == nil {
		log.Fatal("client is nil")
	}
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}
	publicKey := privateKey.PublicKey
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	address := crypto.PubkeyToAddress(publicKey)
	nonce, err := client.PendingNonceAt(context.Background(), address)
	if err != nil {
		log.Fatal(err)
	}
	value := big.NewInt(1000000000)
	gasLimit := uint64(21000)
	maxPriorityFeePerGas := big.NewInt(100000)
	maxFeePerGas := big.NewInt(2000000)
	// gasPrice, err := client.SuggestGasPrice(context.Background())
	toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")
	var data []byte
	lagecyTx := &types.DynamicFeeTx{
		ChainID:   chainId,
		Nonce:     nonce,
		GasTipCap: maxPriorityFeePerGas, // priority fee
		GasFeeCap: maxFeePerGas,         // max fee
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     value,
		Data:      data,
	}
	tx := types.NewTx(lagecyTx)
	signer := types.LatestSignerForChainID(chainId)
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		panic(fmt.Sprintf("signature tx fail %v", err))
	}
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		panic(fmt.Sprintf("broadcast tx fail %v", err))
	}
	fmt.Println("transaction hash:", signedTx.Hash().Hex())
}
func transferToken(client *ethclient.Client) {
	const erc20ABI = `[
	{
		"constant": false,
		"input": [
			{"name":"_to", "type":"address"},
			{"name":"_value", "type":"uint256"}
		],
		"name":"transfer",
		"outputs": [{"name":"", "type":"bool"}],
		"type": "function"
	}
	]`
	if client == nil {
		panic("client is nil")
	}
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey
	fromAddress := crypto.PubkeyToAddress(publicKey)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		panic(err)
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		panic(err)
	}
	contractAddress := common.HexToAddress("0x12312123")
	toAddress := common.HexToAddress("0x1231231231")
	decimals := 18
	amount := big.NewInt(1)
	amount = new(big.Int).Mul(amount, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
	parseABI, err := abi.JSON(bytes.NewReader(json.RawMessage(erc20ABI)))
	if err != nil {
		panic(fmt.Sprintf("parse abi failed: %v\n", err))
	}
	data, err := parseABI.Pack("transfer", toAddress, amount)
	if err != nil {
		panic(fmt.Sprintf("encode transfer data fail: %v\n", err))
	}
	gasLimit := uint64(1000000)
	maxPriorityFeePerGas := big.NewInt(200000000)
	maxFeePerGas := big.NewInt(3000000000)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainId,
		Nonce:     nonce,
		GasTipCap: maxPriorityFeePerGas,
		GasFeeCap: maxFeePerGas,
		Gas:       gasLimit,
		To:        &contractAddress,
		Value:     big.NewInt(0),
		Data:      data,
	})
	signer := types.LatestSignerForChainID(chainId)
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		panic(fmt.Sprintf("signature tx fail: %v\n", err))
	}
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		panic(fmt.Sprintf("broadcase tx fail: %v\n", err))
	}
	fmt.Printf("token transfer is broadcasted. address is %s\n", signedTx.Hash().Hex())
}
func listenBlock(client *ethclient.Client) {
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(ctx, headers)
	if err != nil {
		panic(fmt.Sprintf("subscribe new header fail: %v\n", err))
	}
	fmt.Println("begin to listen...")
	for {
		select {
		case err := <-sub.Err():
			panic(fmt.Sprintf("subscribe err: %v\n", err))
		case header := <-headers:
			fmt.Printf("new block %d, hash: %v\n", header.Number, header.Hash().Hex())
			block, err := client.BlockByHash(ctx, header.Hash())
			if err != nil {
				fmt.Printf("fail to get whole block: %v\n", err)
				continue
			}
			fmt.Println("number of transactions is", len(block.Transactions()))
		}
	}
}
