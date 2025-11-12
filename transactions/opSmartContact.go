package transactions

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	RPC_URL          = "https://sepolia.infura.io/v3/你的Infura项目ID"
	ERC20_REWARD_ABI = `[{
		"constant":false,
		"inputs":[
			{"name":"_to","type":"address"},
			{"name":"_value","type":"uint256"}
		],
		"name":"transfer",
		"outputs":[{"name":"","type":"bool"}],
		"type":"function"
	}]`
	REWARD_TOKEN_ADDR   = "0xlength_40"
	BACKEND_PRIVATE_KEY = "0xlength_64"
	CHAINID             = 11155111
	REWARD_AMOUNT       = 100000000000000000
	MAX_TRY_TIMES       = 3
)

type RewardService struct {
	client      *ethclient.Client
	contractABI abi.ABI
	tokenAddr   common.Address
	backendKey  *ecdsa.PrivateKey
	chainID     *big.Int
}

func NewRewardService() (*RewardService, error) {
	client, err := ethclient.Dial(RPC_URL)
	if err != nil {
		return nil, fmt.Errorf("connect RPC fail: %v", err)
	}
	parsedABI, err := abi.JSON(bytes.NewReader(json.RawMessage(ERC20_REWARD_ABI)))
	if err != nil {
		return nil, fmt.Errorf("ABI decode fail: %v", err)
	}
	privateKey, err := crypto.HexToECDSA(BACKEND_PRIVATE_KEY[2:])
	if err != nil {
		return nil, fmt.Errorf("private key decode fail: %v", err)
	}
	return &RewardService{
		client:      client,
		contractABI: parsedABI,
		tokenAddr:   common.HexToAddress(REWARD_TOKEN_ADDR),
		backendKey:  privateKey,
		chainID:     big.NewInt(CHAINID),
	}, nil
}
func (s *RewardService) CheckUserEligibility(userAddr common.Address) (bool, error) {
	// check if is user eligible to receive reward
	// check off chain user status, or check other contract interface
	fmt.Printf("check user (%s) eligibility", userAddr.Hex())
	return true, nil
}
func (s *RewardService) GetBackendNonce() (uint64, error) {
	backendAddr := crypto.PubkeyToAddress(s.backendKey.PublicKey)
	nonce, err := s.client.PendingNonceAt(context.Background(), backendAddr)
	if err != nil {
		return 0, fmt.Errorf("fail to get nonce:%w", err)
	}
	return nonce, nil
}
func (s *RewardService) IssueReward(userAddr common.Address) (string, error) {
	eligible, err := s.CheckUserEligibility(userAddr)
	if err != nil {
		return "", fmt.Errorf("user validation fail: %w", err)
	}
	if !eligible {
		return "", fmt.Errorf("user(%s) is not eligible for reward", userAddr.Hex())
	}
	data, err := s.contractABI.Pack("transfer", userAddr, big.NewInt(REWARD_AMOUNT))
	if err != nil {
		return "", fmt.Errorf("contract encode err: %w", err)
	}
	nonce, err := s.GetBackendNonce()
	if err != nil {
		return "", fmt.Errorf("get nonce err: %w", err)
	}
	gasLimit := uint64(50000)
	maxPriorityFee := big.NewInt(2000000000)
	maxFee := big.NewInt(30000000000)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   s.chainID,
		Nonce:     nonce,
		GasTipCap: maxPriorityFee,
		GasFeeCap: maxFee,
		Gas:       gasLimit,
		To:        &s.tokenAddr,
		Value:     big.NewInt(0),
		Data:      data,
	})
	signer := types.LatestSignerForChainID(s.chainID)
	signedTx, err := types.SignTx(tx, signer, s.backendKey)
	if err != nil {
		return "", fmt.Errorf("signature fail: %w", err)
	}
	var txHash string
	for i := 0; i < MAX_TRY_TIMES; i++ {
		err = s.client.SendTransaction(context.Background(), signedTx)
		if err == nil {
			txHash = signedTx.Hash().Hex()
			fmt.Printf("broadcast transaction success: %s", txHash)
			break
		}
		fmt.Printf("%d times broadcast transaction fail: %v\n", i+1, err)
		time.Sleep(2 * time.Second)
	}
	err = s.WaitForTxConfirmation(signedTx.Hash())
	if err != nil {
		return txHash, fmt.Errorf("transaction fail: %w", err)
	}
	return "", nil
}
func (s *RewardService) WaitForTxConfirmation(txHash common.Hash) error {
	fmt.Println("waiting for transaction confirmation:", txHash.Hex())
	for {
		receipt, err := s.client.TransactionReceipt(context.Background(), txHash)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		if receipt.Status == types.ReceiptStatusSuccessful {
			fmt.Println("transaction confirmed. block number:", receipt.BlockNumber.String())
			return nil
		}
		return fmt.Errorf("transaction failed: block number: %d, status: %d", receipt.BlockNumber.Uint64(), receipt.Status)
	}
}
