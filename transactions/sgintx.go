package transactions

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func GetLegacyTransactionHash(tx *types.Transaction, chainID *big.Int) common.Hash {
	signer := types.NewEIP155Signer(chainID)
	return signer.Hash(tx)
}
func ExampleLegacyTxHash() {
	nonce := uint64(0)
	to := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	value := big.NewInt(10000000000000000)
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(10000000)
	data := []byte{}
	tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
	chainID := big.NewInt(1)
	signHash := GetLegacyTransactionHash(tx, chainID)
	fmt.Println("Legacy transaction hash:", signHash.Hex())
}
func GetEIP1559TxSignHash(tx *types.Transaction, chainID *big.Int) common.Hash {
	signer := types.NewLondonSigner(chainID)
	return signer.Hash(tx)
}
func ExampleEIP1559TxHash() {
	chainID := big.NewInt(1)
	nonce := uint64(0)
	to := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	value := big.NewInt(10022200000)
	gasLimit := uint64(21000)
	maxPrioirtyFee := big.NewInt(200000000)
	maxFee := big.NewInt(3000000000)
	data := []byte{}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		To:        &to,
		Value:     value,
		Gas:       gasLimit,
		Data:      data,
		GasFeeCap: maxFee,
		GasTipCap: maxPrioirtyFee,
	})
	signHash := GetEIP1559TxSignHash(tx, chainID)
	fmt.Println("EIP1559 transaction hash:", signHash.Hex())
}

// EIP191, 消息哈希 = keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
func MessageSignHash() {
	message := []byte("hello, ethereum!")
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	signHash := crypto.Keccak256Hash([]byte(prefix), message)
	fmt.Println("message signed hash:", signHash.Hex())
}

func SignTxHash(signHash common.Hash) {
	privateKey, err := crypto.HexToECDSA("0x1231231231")
	if err != nil {
		panic(fmt.Sprintf("get private key err: %v\n", err))
	}
	signature, err := crypto.Sign(signHash.Bytes(), privateKey)
	// signature 是65字节：前32字节r，中间32字节s，最后1字节v
	if err != nil {
		panic(fmt.Sprintf("sign the hash err: %v\n", err))
	}
	// recover public key from signature
	publicKey, err := crypto.SigToPub(signHash.Bytes(), signature)
	if err != nil {
		panic(fmt.Sprintf("signature to pubkey err: %v\n", err))
	}
	address := crypto.PubkeyToAddress(*publicKey)
	fmt.Println("signature address:", address.Hex())
}
