package polymarketcontracts

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ivanzzeth/ethclient"
	"github.com/ivanzzeth/ethsig"
	collateral_offramp "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/collateral-offramp"
	collateral_onramp "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/collateral-onramp"
	collateral_token "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/collateral-token"
	conditional_tokens "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/conditional-tokens"
	ctf_collateral_adapter "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/ctf-collateral-adapter"
	"github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/erc20"
	exchange_v2 "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/exchange-v2"
	gnosissafe "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/gnosis-safe-l2"
	neg_risk_ctf_collateral_adapter "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/neg-risk-ctf-collateral-adapter"
	neg_risk_v2 "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/neg-risk-v2"
	negriskfees "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/neg-risk-fees"
	permissioned_ramp "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/permissioned-ramp"
	safeproxyfactory "github.com/ivanzzeth/polymarket-go-contracts/v2/contracts/safe-proxy-factory"
	"github.com/ivanzzeth/ethsig/eip712"
	"github.com/ivanzzeth/polymarket-go-contracts/v2/sender"
	"github.com/ivanzzeth/polymarket-go-contracts/v2/signer"
)

// TokenStatus tracks whether a token's wrap/unwrap operations are enabled.
type TokenStatus struct {
	WrapEnabled   bool
	UnwrapEnabled bool
	LastChecked   time.Time
}

// V2BalanceInfo holds pUSD and USDC.e balances plus V2-relevant allowances and approvals.
// Total = PUSDBalance + USDCEBalance is the effective collateral available for trading.
type V2BalanceInfo struct {
	PUSDBalance  *big.Int
	USDCBalance  *big.Int
	USDCEBalance *big.Int
	Total        *big.Int

	USDCAllowanceOnramp  *big.Int
	USDCEAllowanceOnramp *big.Int

	PUSDAllowanceExchangeV2        *big.Int
	PUSDAllowanceNegRiskExchangeV2 *big.Int
	PUSDAllowanceNegRiskAdapter    *big.Int // V1 NegRiskAdapter — still required by CLOB V2 for neg-risk markets
	PUSDAllowanceCtfAdapter        *big.Int
	PUSDAllowanceNegRiskCtfAdapter *big.Int
	PUSDAllowanceOfframp           *big.Int

	CTFApprovedExchangeV2                  bool
	CTFApprovedNegRiskExchangeV2           bool
	CTFApprovedCtfCollateralAdapter        bool
	CTFApprovedNegRiskCtfCollateralAdapter bool
}

// ContractInterfaceV2 provides a clean V2 API where pUSD is the default collateral.
// It delegates to the same shared txExecutor and calldata builders used by V1.
type ContractInterfaceV2 struct {
	chainID *big.Int
	config  *ContractConfig
	client  ethclient.EthClientInterface
	executor *txExecutor

	// V2 contracts
	exchangeV2                  *exchange_v2.ExchangeV2
	negRiskExchangeV2           *neg_risk_v2.NegRiskV2
	collateralToken             *collateral_token.CollateralToken
	usdc                        *erc20.Erc20
	usdce                       *erc20.Erc20
	conditionalTokens           *conditional_tokens.ConditionalTokens
	collateralOnramp            *collateral_onramp.CollateralOnramp
	collateralOfframp           *collateral_offramp.CollateralOfframp
	ctfCollateralAdapter        *ctf_collateral_adapter.CtfCollateralAdapter
	negRiskCtfCollateralAdapter *neg_risk_ctf_collateral_adapter.NegRiskCtfCollateralAdapter
	permissionedRamp            *permissioned_ramp.PermissionedRamp

	// Safe support (migrated from V1 for backward compatibility)
	safeProxyFactory *safeproxyfactory.SafeProxyFactory // SafeProxyFactory contract
	safeAddressCache sync.Map                           // Cache for Safe addresses (key: EOA hex string, value: Safe address)

	// Token status tracking (lazy refresh)
	tokenStatusMu sync.RWMutex
	tokenStatus   map[common.Address]*TokenStatus
	statusTTL     time.Duration // Default 5 minutes

	// Optional auto-routing fields (set via functional options)
	signatureType      SignatureType
	eoaTradingSigner   signer.EOATradingSigner
	safeTradingSigner  signer.SafeTradingSigner
}

// ContractInterfaceV2Option configures optional fields on ContractInterfaceV2.
type ContractInterfaceV2Option func(*ContractInterfaceV2)

// WithV2SignatureType sets the signature type for auto-routing convenience methods.
// When using SignatureTypePolyGnosisSafe, you must also pass WithV2SafeSigner.
func WithV2SignatureType(st SignatureType) ContractInterfaceV2Option {
	return func(v *ContractInterfaceV2) {
		v.signatureType = st
	}
}

// WithV2SafeSigner sets the Safe trading signer and automatically sets
// signatureType to SignatureTypePolyGnosisSafe.
func WithV2SafeSigner(s signer.SafeTradingSigner) ContractInterfaceV2Option {
	return func(v *ContractInterfaceV2) {
		if s == nil {
			return
		}
		v.safeTradingSigner = s
		v.signatureType = SignatureTypePolyGnosisSafe
	}
}

// WithV2EOASigner sets the EOA trading signer for SignatureTypeEOA.
func WithV2EOASigner(s signer.EOATradingSigner) ContractInterfaceV2Option {
	return func(v *ContractInterfaceV2) {
		if s == nil {
			return
		}
		v.eoaTradingSigner = s
		v.signatureType = SignatureTypeEOA
	}
}

// NewContractInterfaceV2 creates a V2 interface. All V2 contract addresses in config must be non-zero.
// V2 is fully self-contained and does not depend on V1 ContractInterface.
func NewContractInterfaceV2(
	client ethclient.EthClientInterface,
	config *ContractConfig,
	txSender sender.TransactionSender,
	chainID *big.Int,
	opts ...ContractInterfaceV2Option,
) (*ContractInterfaceV2, error) {
	if config.ExchangeV2 == (common.Address{}) {
		return nil, fmt.Errorf("V2 not configured: ExchangeV2 address is zero")
	}

	exchV2, err := exchange_v2.NewExchangeV2(config.ExchangeV2, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create ExchangeV2 binding: %w", err)
	}
	nrV2, err := neg_risk_v2.NewNegRiskV2(config.NegRiskExchangeV2, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create NegRiskV2 binding: %w", err)
	}
	ct, err := collateral_token.NewCollateralToken(config.CollateralToken, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create CollateralToken binding: %w", err)
	}
	usdce, err := erc20.NewErc20(config.Collateral, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create USDC.e binding: %w", err)
	}
	var usdc *erc20.Erc20
	if config.USDC != (common.Address{}) {
		usdc, err = erc20.NewErc20(config.USDC, client)
		if err != nil {
			return nil, fmt.Errorf("failed to create USDC binding: %w", err)
		}
	}
	ctf, err := conditional_tokens.NewConditionalTokens(config.ConditionalTokens, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create ConditionalTokens binding: %w", err)
	}
	onramp, err := collateral_onramp.NewCollateralOnramp(config.CollateralOnramp, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create CollateralOnramp binding: %w", err)
	}
	offramp, err := collateral_offramp.NewCollateralOfframp(config.CollateralOfframp, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create CollateralOfframp binding: %w", err)
	}
	ctfAdapter, err := ctf_collateral_adapter.NewCtfCollateralAdapter(config.CtfCollateralAdapter, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create CtfCollateralAdapter binding: %w", err)
	}
	nrCtfAdapter, err := neg_risk_ctf_collateral_adapter.NewNegRiskCtfCollateralAdapter(config.NegRiskCtfCollateralAdapter, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create NegRiskCtfCollateralAdapter binding: %w", err)
	}
	pr, err := permissioned_ramp.NewPermissionedRamp(config.PermissionedRamp, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create PermissionedRamp binding: %w", err)
	}

	// Initialize SafeProxyFactory for Safe address computation (migrated from V1)
	var safeFactory *safeproxyfactory.SafeProxyFactory
	if config.SafeProxyFactory != (common.Address{}) {
		safeFactory, err = safeproxyfactory.NewSafeProxyFactory(config.SafeProxyFactory, client)
		if err != nil {
			return nil, fmt.Errorf("failed to create SafeProxyFactory binding: %w", err)
		}
	}

	// Create V2 instance first (without executor)
	v2 := &ContractInterfaceV2{
		chainID: chainID,
		config:  config,
		client:  client,

		exchangeV2:                  exchV2,
		negRiskExchangeV2:           nrV2,
		collateralToken:             ct,
		usdc:                        usdc,
		usdce:                       usdce,
		conditionalTokens:           ctf,
		collateralOnramp:            onramp,
		collateralOfframp:           offramp,
		ctfCollateralAdapter:        ctfAdapter,
		negRiskCtfCollateralAdapter: nrCtfAdapter,
		permissionedRamp:            pr,

		safeProxyFactory: safeFactory,

		tokenStatus: make(map[common.Address]*TokenStatus),
		statusTTL:   5 * time.Minute,
	}

	for _, opt := range opts {
		opt(v2)
	}

	// Create executor using v2's own methods (no dependency on V1)
	v2.executor = &txExecutor{
		client:      client,
		txSender:    txSender,
		getSafeAddr: v2.GetSafeAddress,
		execSafeTx:  v2.ExecuteTransactionBySafeAndSingleSigner,
	}

	// Initial token status check (non-blocking, just log warnings)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v2.refreshTokenStatus(ctx); err != nil {
		// Log warning but don't fail initialization
		fmt.Printf("Warning: failed to refresh token status during initialization: %v\n", err)
	}

	return v2, nil
}

// --- Read operations ---

// GetBalances returns pUSD/USDC.e balances and V2-relevant allowances/approvals.
func (v *ContractInterfaceV2) GetBalances(ctx context.Context, address common.Address) (*V2BalanceInfo, error) {
	return v.GetBalancesAtBlock(ctx, address, nil)
}

// GetBalancesAtBlock returns balances at a specific block (nil = latest).
func (v *ContractInterfaceV2) GetBalancesAtBlock(ctx context.Context, address common.Address, blockNumber *big.Int) (*V2BalanceInfo, error) {
	opts := &bind.CallOpts{Context: ctx, BlockNumber: blockNumber}
	info := &V2BalanceInfo{}

	pusdBal, err := v.collateralToken.BalanceOf(opts, address)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD balance: %w", err)
	}
	info.PUSDBalance = pusdBal

	usdceBal, err := v.usdce.BalanceOf(opts, address)
	if err != nil {
		return nil, fmt.Errorf("failed to get USDC.e balance: %w", err)
	}
	info.USDCEBalance = usdceBal

	info.USDCEAllowanceOnramp, err = v.usdce.Allowance(opts, address, v.config.CollateralOnramp)
	if err != nil {
		return nil, fmt.Errorf("failed to get USDC.e allowance for CollateralOnramp: %w", err)
	}

	if v.usdc != nil {
		usdcBal, err := v.usdc.BalanceOf(opts, address)
		if err != nil {
			return nil, fmt.Errorf("failed to get USDC balance: %w", err)
		}
		info.USDCBalance = usdcBal

		info.USDCAllowanceOnramp, err = v.usdc.Allowance(opts, address, v.config.CollateralOnramp)
		if err != nil {
			return nil, fmt.Errorf("failed to get USDC allowance for CollateralOnramp: %w", err)
		}
	}

	info.PUSDAllowanceExchangeV2, err = v.collateralToken.Allowance(opts, address, v.config.ExchangeV2)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD allowance for ExchangeV2: %w", err)
	}
	info.PUSDAllowanceNegRiskExchangeV2, err = v.collateralToken.Allowance(opts, address, v.config.NegRiskExchangeV2)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD allowance for NegRiskExchangeV2: %w", err)
	}
	info.PUSDAllowanceNegRiskAdapter, err = v.collateralToken.Allowance(opts, address, v.config.NegRiskAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD allowance for NegRiskAdapter: %w", err)
	}
	info.PUSDAllowanceCtfAdapter, err = v.collateralToken.Allowance(opts, address, v.config.CtfCollateralAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD allowance for CtfCollateralAdapter: %w", err)
	}
	info.PUSDAllowanceNegRiskCtfAdapter, err = v.collateralToken.Allowance(opts, address, v.config.NegRiskCtfCollateralAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD allowance for NegRiskCtfCollateralAdapter: %w", err)
	}
	info.PUSDAllowanceOfframp, err = v.collateralToken.Allowance(opts, address, v.config.CollateralOfframp)
	if err != nil {
		return nil, fmt.Errorf("failed to get pUSD allowance for CollateralOfframp: %w", err)
	}

	info.CTFApprovedExchangeV2, err = v.conditionalTokens.IsApprovedForAll(opts, address, v.config.ExchangeV2)
	if err != nil {
		return nil, fmt.Errorf("failed to check CTF approval for ExchangeV2: %w", err)
	}
	info.CTFApprovedNegRiskExchangeV2, err = v.conditionalTokens.IsApprovedForAll(opts, address, v.config.NegRiskExchangeV2)
	if err != nil {
		return nil, fmt.Errorf("failed to check CTF approval for NegRiskExchangeV2: %w", err)
	}
	info.CTFApprovedCtfCollateralAdapter, err = v.conditionalTokens.IsApprovedForAll(opts, address, v.config.CtfCollateralAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to check CTF approval for CtfCollateralAdapter: %w", err)
	}
	info.CTFApprovedNegRiskCtfCollateralAdapter, err = v.conditionalTokens.IsApprovedForAll(opts, address, v.config.NegRiskCtfCollateralAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to check CTF approval for NegRiskCtfCollateralAdapter: %w", err)
	}

	info.Total = new(big.Int).Add(pusdBal, usdceBal)

	return info, nil
}

// --- Getters for V2 contract bindings ---

func (v *ContractInterfaceV2) ExchangeV2() *exchange_v2.ExchangeV2                   { return v.exchangeV2 }
func (v *ContractInterfaceV2) NegRiskExchangeV2() *neg_risk_v2.NegRiskV2             { return v.negRiskExchangeV2 }
func (v *ContractInterfaceV2) CollateralToken() *collateral_token.CollateralToken     { return v.collateralToken }
func (v *ContractInterfaceV2) NativeUSDC() *erc20.Erc20                               { return v.usdc }
func (v *ContractInterfaceV2) USDCE() *erc20.Erc20                                   { return v.usdce }
func (v *ContractInterfaceV2) ConditionalTokens() *conditional_tokens.ConditionalTokens { return v.conditionalTokens }

// GetConditionalTokens is a backward-compatible alias for ConditionalTokens.
func (v *ContractInterfaceV2) GetConditionalTokens() *conditional_tokens.ConditionalTokens { return v.conditionalTokens }

func (v *ContractInterfaceV2) CollateralOnramp() *collateral_onramp.CollateralOnramp { return v.collateralOnramp }
func (v *ContractInterfaceV2) CollateralOfframp() *collateral_offramp.CollateralOfframp { return v.collateralOfframp }
func (v *ContractInterfaceV2) CtfCollateralAdapter() *ctf_collateral_adapter.CtfCollateralAdapter { return v.ctfCollateralAdapter }
func (v *ContractInterfaceV2) NegRiskCtfCollateralAdapter() *neg_risk_ctf_collateral_adapter.NegRiskCtfCollateralAdapter { return v.negRiskCtfCollateralAdapter }
func (v *ContractInterfaceV2) PermissionedRamp() *permissioned_ramp.PermissionedRamp { return v.permissionedRamp }

func (v *ContractInterfaceV2) GetConfig() *ContractConfig                              { return v.config }
func (v *ContractInterfaceV2) GetClient() ethclient.EthClientInterface                 { return v.client }
func (v *ContractInterfaceV2) GetSafeProxyFactory() *safeproxyfactory.SafeProxyFactory { return v.safeProxyFactory }
func (v *ContractInterfaceV2) GetSignatureType() SignatureType                         { return v.signatureType }
func (v *ContractInterfaceV2) GetEOATradingSigner() signer.EOATradingSigner             { return v.eoaTradingSigner }
func (v *ContractInterfaceV2) GetSafeTradingSigner() signer.SafeTradingSigner           { return v.safeTradingSigner }
func (v *ContractInterfaceV2) GetChainID() *big.Int                                    { return v.chainID }

// GetExchange returns the V2 exchange contract binding.
func (v *ContractInterfaceV2) GetExchange() *exchange_v2.ExchangeV2 { return v.exchangeV2 }

// GetNegRiskFees returns nil — V2 uses NegRiskExchangeV2's FeeCharged event
// (not a separate NegRiskFees contract). Framework handles V2 fee events separately.
func (v *ContractInterfaceV2) GetNegRiskFees() *negriskfees.NegRiskFees { return nil }

// --- EnableTrading ---

// EnableTradingOption configures optional behavior for EnableTrading methods.
type EnableTradingOption func(*enableTradingConfig)

type enableTradingConfig struct {
	autoWrapToPUSD bool
}

// WithAutoWrapToPUSD wraps all USDC and USDC.e balances to pUSD after approvals.
func WithAutoWrapToPUSD() EnableTradingOption {
	return func(c *enableTradingConfig) {
		c.autoWrapToPUSD = true
	}
}

// EnableTradingForEOA approves pUSD to adapters/offramp and sets CTF approvals for V2 exchanges/adapters.
func (v *ContractInterfaceV2) EnableTradingForEOA(ctx context.Context, opts ...EnableTradingOption) ([]common.Hash, error) {
	addr, err := v.getEOAAddress()
	if err != nil {
		return nil, err
	}
	calls, err := v.enableTradingCalls(ctx, addr, opts...)
	if err != nil {
		return nil, err
	}
	return v.executor.executeBatchEOA(calls)
}

// EnableTradingForSafe approves pUSD to adapters/offramp and sets CTF approvals for V2 exchanges/adapters via Safe.
func (v *ContractInterfaceV2) EnableTradingForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, opts ...EnableTradingOption) ([]common.Hash, error) {
	safeAddr, err := v.GetSafeAddress(safeSigner.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("failed to get Safe address: %w", err)
	}
	calls, err := v.enableTradingCalls(ctx, safeAddr, opts...)
	if err != nil {
		return nil, err
	}
	return v.executor.executeBatchSafe(safeSigner, chainID, calls)
}

func (v *ContractInterfaceV2) enableTradingCalls(ctx context.Context, address common.Address, opts ...EnableTradingOption) ([]contractCall, error) {
	cfg := &enableTradingConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	info, err := v.GetBalances(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to check current allowances: %w", err)
	}

	calls, err := v.buildEnableTradingCalls(info)
	if err != nil {
		return nil, err
	}

	// Auto-wrap USDC/USDC.e to pUSD if requested
	if cfg.autoWrapToPUSD {
		if info.USDCEBalance != nil && info.USDCEBalance.Sign() > 0 {
			wrapCall, err := buildWrapCall(v.config.CollateralOnramp, v.config.Collateral, address, info.USDCEBalance)
			if err != nil {
				return nil, fmt.Errorf("failed to build USDC.e wrap call: %w", err)
			}
			calls = append(calls, wrapCall)
		}

		if info.USDCBalance != nil && info.USDCBalance.Sign() > 0 {
			wrapCall, err := buildWrapCall(v.config.CollateralOnramp, v.config.USDC, address, info.USDCBalance)
			if err != nil {
				return nil, fmt.Errorf("failed to build USDC wrap call: %w", err)
			}
			calls = append(calls, wrapCall)
		}
	}

	return calls, nil
}

func (v *ContractInterfaceV2) buildEnableTradingCalls(info *V2BalanceInfo) ([]contractCall, error) {
	maxApproval := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	zero := big.NewInt(0)
	needsApproval := func(current *big.Int) bool {
		return current == nil || current.Cmp(zero) == 0
	}

	var calls []contractCall

	if needsApproval(info.USDCEAllowanceOnramp) {
		call, err := buildERC20ApproveCall(v.config.Collateral, v.config.CollateralOnramp, maxApproval)
		if err != nil {
			return nil, fmt.Errorf("failed to build USDC.e approve for CollateralOnramp: %w", err)
		}
		calls = append(calls, call)
	}

	if v.config.USDC != (common.Address{}) && needsApproval(info.USDCAllowanceOnramp) {
		call, err := buildERC20ApproveCall(v.config.USDC, v.config.CollateralOnramp, maxApproval)
		if err != nil {
			return nil, fmt.Errorf("failed to build USDC approve for CollateralOnramp: %w", err)
		}
		calls = append(calls, call)
	}

	pUSDApprovals := []struct {
		spender common.Address
		current *big.Int
	}{
		{v.config.ExchangeV2, info.PUSDAllowanceExchangeV2},
		{v.config.NegRiskExchangeV2, info.PUSDAllowanceNegRiskExchangeV2},
		{v.config.NegRiskAdapter, info.PUSDAllowanceNegRiskAdapter},
		{v.config.CtfCollateralAdapter, info.PUSDAllowanceCtfAdapter},
		{v.config.NegRiskCtfCollateralAdapter, info.PUSDAllowanceNegRiskCtfAdapter},
		{v.config.CollateralOfframp, info.PUSDAllowanceOfframp},
	}
	for _, a := range pUSDApprovals {
		if needsApproval(a.current) {
			call, err := buildERC20ApproveCall(v.config.CollateralToken, a.spender, maxApproval)
			if err != nil {
				return nil, fmt.Errorf("failed to build pUSD approve for %s: %w", a.spender.Hex(), err)
			}
			calls = append(calls, call)
		}
	}

	ctfApprovals := []struct {
		operator common.Address
		approved bool
	}{
		{v.config.ExchangeV2, info.CTFApprovedExchangeV2},
		{v.config.NegRiskExchangeV2, info.CTFApprovedNegRiskExchangeV2},
		{v.config.CtfCollateralAdapter, info.CTFApprovedCtfCollateralAdapter},
		{v.config.NegRiskCtfCollateralAdapter, info.CTFApprovedNegRiskCtfCollateralAdapter},
	}
	for _, a := range ctfApprovals {
		if !a.approved {
			call, err := buildSetApprovalForAllCall(v.config.ConditionalTokens, a.operator, true)
			if err != nil {
				return nil, fmt.Errorf("failed to build CTF setApprovalForAll for %s: %w", a.operator.Hex(), err)
			}
			calls = append(calls, call)
		}
	}

	return calls, nil
}

// --- Wrap / Unwrap ---

// validateWrapAsset checks if the asset is a supported collateral token (USDC or USDC.e).
// Both native USDC (0x3c499c...) and bridged USDC.e (0x2791Bca...) are supported by CollateralOnramp.
func (v *ContractInterfaceV2) validateWrapAsset(asset common.Address) error {
	if asset != v.config.Collateral && asset != v.config.USDC {
		return fmt.Errorf("unsupported wrap asset %s: only USDC (%s) and USDC.e (%s) are supported",
			asset.Hex(), v.config.USDC.Hex(), v.config.Collateral.Hex())
	}
	return nil
}

// validateWrapEnabled checks if wrap is currently enabled for the given asset.
func (v *ContractInterfaceV2) validateWrapEnabled(asset common.Address) error {
	status, exists := v.getTokenStatus(asset)
	if !exists {
		return fmt.Errorf("token status not initialized for %s", asset.Hex())
	}
	if !status.WrapEnabled {
		tokenName := "USDC"
		if asset == v.config.Collateral {
			tokenName = "USDC.e"
		}
		return fmt.Errorf("%s wrap is currently paused by Polymarket contracts", tokenName)
	}
	return nil
}

// validateUnwrapEnabled checks if unwrap is currently enabled for the given asset.
func (v *ContractInterfaceV2) validateUnwrapEnabled(asset common.Address) error {
	status, exists := v.getTokenStatus(asset)
	if !exists {
		return fmt.Errorf("token status not initialized for %s", asset.Hex())
	}
	if !status.UnwrapEnabled {
		tokenName := "USDC"
		if asset == v.config.Collateral {
			tokenName = "USDC.e"
		}
		return fmt.Errorf("%s unwrap is currently paused by Polymarket contracts", tokenName)
	}
	return nil
}

// getEOAAddress returns the EOA address from txSender via type assertion.
func (v *ContractInterfaceV2) getEOAAddress() (common.Address, error) {
	type addressGetter interface {
		GetAddress() common.Address
	}
	if ag, ok := v.executor.txSender.(addressGetter); ok {
		return ag.GetAddress(), nil
	}
	return common.Address{}, fmt.Errorf("txSender does not implement GetAddress; amount must be specified explicitly")
}

// resolveAssetBalance queries the on-chain balance of asset for addr.
// Used to resolve nil amount (wrap/unwrap full balance).
func (v *ContractInterfaceV2) resolveAssetBalance(ctx context.Context, addr, asset common.Address) (*big.Int, error) {
	opts := &bind.CallOpts{Context: ctx}
	if asset == v.config.Collateral {
		return v.usdce.BalanceOf(opts, addr)
	}
	if v.usdc != nil && asset == v.config.USDC {
		return v.usdc.BalanceOf(opts, addr)
	}
	return nil, fmt.Errorf("unknown asset %s for balance query", asset.Hex())
}

// resolvePUSDBalance queries the on-chain pUSD balance for addr.
func (v *ContractInterfaceV2) resolvePUSDBalance(ctx context.Context, addr common.Address) (*big.Int, error) {
	opts := &bind.CallOpts{Context: ctx}
	return v.collateralToken.BalanceOf(opts, addr)
}

// WrapToPUSDForEOA wraps USDC/USDC.e to pUSD via the CollateralOnramp.
// If amount is nil, wraps the sender's entire asset balance.
func (v *ContractInterfaceV2) WrapToPUSDForEOA(ctx context.Context, asset common.Address, to common.Address, amount *big.Int) (common.Hash, error) {
	if err := v.validateWrapAsset(asset); err != nil {
		return common.Hash{}, err
	}
	if err := v.ensureTokenStatus(ctx, asset); err != nil {
		return common.Hash{}, fmt.Errorf("failed to refresh token status: %w", err)
	}
	if err := v.validateWrapEnabled(asset); err != nil {
		return common.Hash{}, err
	}
	if amount == nil {
		addr, err := v.getEOAAddress()
		if err != nil {
			return common.Hash{}, err
		}
		amount, err = v.resolveAssetBalance(ctx, addr, asset)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to resolve full balance for wrap: %w", err)
		}
	}
	call, err := buildWrapCall(v.config.CollateralOnramp, asset, to, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// WrapToPUSDForSafe wraps USDC/USDC.e to pUSD via Safe.
// If amount is nil, wraps the Safe's entire asset balance.
func (v *ContractInterfaceV2) WrapToPUSDForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, asset common.Address, to common.Address, amount *big.Int) (common.Hash, error) {
	if err := v.validateWrapAsset(asset); err != nil {
		return common.Hash{}, err
	}
	if err := v.ensureTokenStatus(ctx, asset); err != nil {
		return common.Hash{}, fmt.Errorf("failed to refresh token status: %w", err)
	}
	if err := v.validateWrapEnabled(asset); err != nil {
		return common.Hash{}, err
	}
	if amount == nil {
		safeAddr, err := v.GetSafeAddress(safeSigner.GetAddress())
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to get safe address for balance: %w", err)
		}
		amount, err = v.resolveAssetBalance(ctx, safeAddr, asset)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to resolve full balance for wrap: %w", err)
		}
	}
	call, err := buildWrapCall(v.config.CollateralOnramp, asset, to, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// UnwrapFromPUSDForEOA unwraps pUSD to USDC/USDC.e via the CollateralOfframp.
// If amount is nil, unwraps the sender's entire pUSD balance.
func (v *ContractInterfaceV2) UnwrapFromPUSDForEOA(ctx context.Context, asset common.Address, to common.Address, amount *big.Int) (common.Hash, error) {
	if err := v.validateWrapAsset(asset); err != nil {
		return common.Hash{}, err
	}
	if err := v.ensureTokenStatus(ctx, asset); err != nil {
		return common.Hash{}, fmt.Errorf("failed to refresh token status: %w", err)
	}
	if err := v.validateUnwrapEnabled(asset); err != nil {
		return common.Hash{}, err
	}
	if amount == nil {
		addr, err := v.getEOAAddress()
		if err != nil {
			return common.Hash{}, err
		}
		amount, err = v.resolvePUSDBalance(ctx, addr)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to resolve full pUSD balance for unwrap: %w", err)
		}
	}
	call, err := buildUnwrapCall(v.config.CollateralOfframp, asset, to, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// UnwrapFromPUSDForSafe unwraps pUSD to USDC/USDC.e via Safe.
// If amount is nil, unwraps the Safe's entire pUSD balance.
func (v *ContractInterfaceV2) UnwrapFromPUSDForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, asset common.Address, to common.Address, amount *big.Int) (common.Hash, error) {
	if err := v.validateWrapAsset(asset); err != nil {
		return common.Hash{}, err
	}
	if err := v.ensureTokenStatus(ctx, asset); err != nil {
		return common.Hash{}, fmt.Errorf("failed to refresh token status: %w", err)
	}
	if err := v.validateUnwrapEnabled(asset); err != nil {
		return common.Hash{}, err
	}
	if amount == nil {
		safeAddr, err := v.GetSafeAddress(safeSigner.GetAddress())
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to get safe address for balance: %w", err)
		}
		amount, err = v.resolvePUSDBalance(ctx, safeAddr)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to resolve full pUSD balance for unwrap: %w", err)
		}
	}
	call, err := buildUnwrapCall(v.config.CollateralOfframp, asset, to, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// --- Split / Merge / Redeem (regular markets via CtfCollateralAdapter) ---

// SplitPositionForEOA splits pUSD into conditional tokens via the CtfCollateralAdapter.
func (v *ContractInterfaceV2) SplitPositionForEOA(ctx context.Context, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildAdapterSplitCall(v.config.CtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// SplitPositionForSafe splits pUSD into conditional tokens via Safe.
func (v *ContractInterfaceV2) SplitPositionForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildAdapterSplitCall(v.config.CtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// MergePositionsForEOA merges conditional tokens back into pUSD via the CtfCollateralAdapter.
func (v *ContractInterfaceV2) MergePositionsForEOA(ctx context.Context, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildAdapterMergeCall(v.config.CtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// MergePositionsForSafe merges conditional tokens back into pUSD via Safe.
func (v *ContractInterfaceV2) MergePositionsForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildAdapterMergeCall(v.config.CtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// RedeemPositionsForEOA redeems conditional tokens for pUSD via the CtfCollateralAdapter.
func (v *ContractInterfaceV2) RedeemPositionsForEOA(ctx context.Context, conditionId [32]byte, indexSets []*big.Int) (common.Hash, error) {
	call, err := buildAdapterRedeemCall(v.config.CtfCollateralAdapter, conditionId, indexSets)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// RedeemPositionsForSafe redeems conditional tokens for pUSD via Safe.
func (v *ContractInterfaceV2) RedeemPositionsForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, conditionId [32]byte, indexSets []*big.Int) (common.Hash, error) {
	call, err := buildAdapterRedeemCall(v.config.CtfCollateralAdapter, conditionId, indexSets)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// --- Split / Merge / Redeem (neg-risk markets via NegRiskCtfCollateralAdapter) ---

// SplitPositionNegRiskForEOA splits pUSD into neg-risk conditional tokens via the NegRiskCtfCollateralAdapter.
func (v *ContractInterfaceV2) SplitPositionNegRiskForEOA(ctx context.Context, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildNegRiskAdapterSplitCall(v.config.NegRiskCtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// SplitPositionNegRiskForSafe splits pUSD into neg-risk conditional tokens via Safe.
func (v *ContractInterfaceV2) SplitPositionNegRiskForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildNegRiskAdapterSplitCall(v.config.NegRiskCtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// MergePositionsNegRiskForEOA merges neg-risk conditional tokens back into pUSD.
func (v *ContractInterfaceV2) MergePositionsNegRiskForEOA(ctx context.Context, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildNegRiskAdapterMergeCall(v.config.NegRiskCtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// MergePositionsNegRiskForSafe merges neg-risk conditional tokens back into pUSD via Safe.
func (v *ContractInterfaceV2) MergePositionsNegRiskForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, conditionId [32]byte, partition []*big.Int, amount *big.Int) (common.Hash, error) {
	call, err := buildNegRiskAdapterMergeCall(v.config.NegRiskCtfCollateralAdapter, conditionId, partition, amount)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// RedeemPositionsNegRiskForEOA redeems neg-risk conditional tokens for pUSD.
func (v *ContractInterfaceV2) RedeemPositionsNegRiskForEOA(ctx context.Context, conditionId [32]byte, indexSets []*big.Int) (common.Hash, error) {
	call, err := buildNegRiskAdapterRedeemCall(v.config.NegRiskCtfCollateralAdapter, conditionId, indexSets)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeEOA(call)
}

// RedeemPositionsNegRiskForSafe redeems neg-risk conditional tokens for pUSD via Safe.
func (v *ContractInterfaceV2) RedeemPositionsNegRiskForSafe(ctx context.Context, safeSigner signer.SafeTradingSigner, chainID *big.Int, conditionId [32]byte, indexSets []*big.Int) (common.Hash, error) {
	call, err := buildNegRiskAdapterRedeemCall(v.config.NegRiskCtfCollateralAdapter, conditionId, indexSets)
	if err != nil {
		return common.Hash{}, err
	}
	return v.executor.executeSafe(safeSigner, chainID, call)
}

// --- Auto-routing convenience methods ---
// These methods dispatch to ForEOA or ForSafe based on signatureType.
// Set via WithV2SafeSigner or WithV2SignatureType options.

func (v *ContractInterfaceV2) getSafeTradingSignerOrErr() (signer.SafeTradingSigner, error) {
	if v.safeTradingSigner == nil {
		return nil, fmt.Errorf("safe trading signer not configured: use WithV2SafeSigner option")
	}
	return v.safeTradingSigner, nil
}

func (v *ContractInterfaceV2) EnableTrading(ctx context.Context, opts ...EnableTradingOption) ([]common.Hash, error) {
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return nil, err
		}
		return v.EnableTradingForSafe(ctx, s, v.chainID, opts...)
	case SignatureTypeEOA:
		return v.EnableTradingForEOA(ctx, opts...)
	default:
		return nil, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) Split(ctx context.Context, conditionId [32]byte, amount *big.Int) (common.Hash, error) {
	partition := []*big.Int{big.NewInt(1), big.NewInt(2)}
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.SplitPositionForSafe(ctx, s, v.chainID, conditionId, partition, amount)
	case SignatureTypeEOA:
		return v.SplitPositionForEOA(ctx, conditionId, partition, amount)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) Merge(ctx context.Context, conditionId [32]byte, amount *big.Int) (common.Hash, error) {
	partition := []*big.Int{big.NewInt(1), big.NewInt(2)}
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.MergePositionsForSafe(ctx, s, v.chainID, conditionId, partition, amount)
	case SignatureTypeEOA:
		return v.MergePositionsForEOA(ctx, conditionId, partition, amount)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) Redeem(ctx context.Context, conditionId [32]byte) (common.Hash, error) {
	indexSets := []*big.Int{big.NewInt(1), big.NewInt(2)}
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.RedeemPositionsForSafe(ctx, s, v.chainID, conditionId, indexSets)
	case SignatureTypeEOA:
		return v.RedeemPositionsForEOA(ctx, conditionId, indexSets)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) SplitNegRisk(ctx context.Context, conditionId [32]byte, amount *big.Int) (common.Hash, error) {
	partition := []*big.Int{big.NewInt(1), big.NewInt(2)}
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.SplitPositionNegRiskForSafe(ctx, s, v.chainID, conditionId, partition, amount)
	case SignatureTypeEOA:
		return v.SplitPositionNegRiskForEOA(ctx, conditionId, partition, amount)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) MergeNegRisk(ctx context.Context, conditionId [32]byte, amount *big.Int) (common.Hash, error) {
	partition := []*big.Int{big.NewInt(1), big.NewInt(2)}
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.MergePositionsNegRiskForSafe(ctx, s, v.chainID, conditionId, partition, amount)
	case SignatureTypeEOA:
		return v.MergePositionsNegRiskForEOA(ctx, conditionId, partition, amount)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) RedeemNegRisk(ctx context.Context, conditionId [32]byte, amounts []*big.Int) (common.Hash, error) {
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.RedeemPositionsNegRiskForSafe(ctx, s, v.chainID, conditionId, amounts)
	case SignatureTypeEOA:
		return v.RedeemPositionsNegRiskForEOA(ctx, conditionId, amounts)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) WrapToPUSD(ctx context.Context, asset common.Address, to common.Address, amount *big.Int) (common.Hash, error) {
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.WrapToPUSDForSafe(ctx, s, v.chainID, asset, to, amount)
	case SignatureTypeEOA:
		return v.WrapToPUSDForEOA(ctx, asset, to, amount)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

func (v *ContractInterfaceV2) UnwrapFromPUSD(ctx context.Context, asset common.Address, to common.Address, amount *big.Int) (common.Hash, error) {
	switch v.signatureType {
	case SignatureTypePolyGnosisSafe:
		s, err := v.getSafeTradingSignerOrErr()
		if err != nil {
			return common.Hash{}, err
		}
		return v.UnwrapFromPUSDForSafe(ctx, s, v.chainID, asset, to, amount)
	case SignatureTypeEOA:
		return v.UnwrapFromPUSDForEOA(ctx, asset, to, amount)
	default:
		return common.Hash{}, fmt.Errorf("unsupported signature type: %v", v.signatureType)
	}
}

// --- Token Status Tracking ---

// checkTokenWrapStatus checks if wrap is paused for the given token.
// Returns true if wrap is enabled, false if paused.
func (v *ContractInterfaceV2) checkTokenWrapStatus(ctx context.Context, asset common.Address) bool {
	opts := &bind.CallOpts{Context: ctx}
	paused, err := v.collateralOnramp.Paused(opts, asset)
	if err != nil {
		return true
	}
	return !paused
}

// checkTokenUnwrapStatus checks if unwrap is paused for the given token.
// Returns true if unwrap is enabled, false if paused.
func (v *ContractInterfaceV2) checkTokenUnwrapStatus(ctx context.Context, asset common.Address) bool {
	opts := &bind.CallOpts{Context: ctx}
	paused, err := v.collateralOfframp.Paused(opts, asset)
	if err != nil {
		return true
	}
	return !paused
}

// refreshTokenStatus checks wrap/unwrap status for all supported tokens.
func (v *ContractInterfaceV2) refreshTokenStatus(ctx context.Context) error {
	v.tokenStatusMu.Lock()
	defer v.tokenStatusMu.Unlock()

	now := time.Now()

	// Check USDC.e
	usdceStatus := &TokenStatus{
		WrapEnabled:   v.checkTokenWrapStatus(ctx, v.config.Collateral),
		UnwrapEnabled: v.checkTokenUnwrapStatus(ctx, v.config.Collateral),
		LastChecked:   now,
	}
	v.tokenStatus[v.config.Collateral] = usdceStatus

	// Check USDC if configured
	if v.config.USDC != (common.Address{}) {
		usdcStatus := &TokenStatus{
			WrapEnabled:   v.checkTokenWrapStatus(ctx, v.config.USDC),
			UnwrapEnabled: v.checkTokenUnwrapStatus(ctx, v.config.USDC),
			LastChecked:   now,
		}
		v.tokenStatus[v.config.USDC] = usdcStatus
	}

	return nil
}

// ensureTokenStatus checks if token status needs refresh (lazy refresh).
// If last check was longer than TTL ago, refreshes the status.
func (v *ContractInterfaceV2) ensureTokenStatus(ctx context.Context, asset common.Address) error {
	v.tokenStatusMu.RLock()
	status, exists := v.tokenStatus[asset]
	needsRefresh := !exists || time.Since(status.LastChecked) > v.statusTTL
	v.tokenStatusMu.RUnlock()

	if needsRefresh {
		return v.refreshTokenStatus(ctx)
	}
	return nil
}

// getTokenStatus returns the current token status (wrap/unwrap enabled).
func (v *ContractInterfaceV2) getTokenStatus(asset common.Address) (*TokenStatus, bool) {
	v.tokenStatusMu.RLock()
	defer v.tokenStatusMu.RUnlock()
	status, exists := v.tokenStatus[asset]
	return status, exists
}

// RefreshTokenStatus manually refreshes token status (exposed for manual refresh).
func (v *ContractInterfaceV2) RefreshTokenStatus(ctx context.Context) error {
	return v.refreshTokenStatus(ctx)
}

// GetTokenStatus returns the current token status (wrap/unwrap enabled) - exported for testing.
func (v *ContractInterfaceV2) GetTokenStatus(asset common.Address) (*TokenStatus, bool) {
	return v.getTokenStatus(asset)
}

// ============================================================================
// Safe Support (Migrated from V1 for Backward Compatibility)
// ============================================================================

// GetSafeAddress computes the Safe address for a given EOA address.
// Migrated from V1 ContractInterface to make V2 fully self-contained.
func (v *ContractInterfaceV2) GetSafeAddress(eoa common.Address) (common.Address, error) {
	if v.safeProxyFactory == nil {
		return common.Address{}, fmt.Errorf("SafeProxyFactory not configured")
	}

	// Check cache first
	if cached, ok := v.safeAddressCache.Load(eoa.Hex()); ok {
		return cached.(common.Address), nil
	}

	// Compute safe address
	safeAddr, err := v.safeProxyFactory.ComputeProxyAddress(nil, eoa)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to compute Safe address: %w", err)
	}

	// Store in cache
	v.safeAddressCache.Store(eoa.Hex(), safeAddr)

	return safeAddr, nil
}

// GetGnosisSafeL2 returns a GnosisSafeL2 contract instance at the given address.
// Migrated from V1 for Safe transaction support.
func (v *ContractInterfaceV2) GetGnosisSafeL2(addr common.Address) (*gnosissafe.GnosisSafeL2, error) {
	return gnosissafe.NewGnosisSafeL2(addr, v.client)
}

// EstimateSafeTxGas estimates the gas required for a Safe transaction execution.
// This uses simulateAndRevert to accurately estimate gas without requiring valid signatures.
// Migrated from V1 for Safe transaction support.
func (v *ContractInterfaceV2) EstimateSafeTxGas(safeAddr, to common.Address, value *big.Int, data []byte, operation SafeOperation) (*big.Int, error) {
	// Parse Safe ABI to encode the simulateAndRevert call
	parsedABI, err := abi.JSON(strings.NewReader(gnosissafe.GnosisSafeL2MetaData.ABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse GnosisSafeL2 ABI: %w", err)
	}

	// Encode the target transaction call data (the transaction we want to simulate)
	// We create the call data for the internal transaction
	var targetCallData []byte
	if len(data) > 0 {
		targetCallData = data
	} else {
		targetCallData = []byte{}
	}

	// Use simulateAndRevert to estimate gas
	// simulateAndRevert(address targetContract, bytes calldataPayload)
	simulateCallData, err := parsedABI.Pack("simulateAndRevert", to, targetCallData)
	if err != nil {
		return nil, fmt.Errorf("failed to pack simulateAndRevert call data: %w", err)
	}

	// Call simulateAndRevert - it will always revert with the execution result
	msg := ethereum.CallMsg{
		To:   &safeAddr,
		Data: simulateCallData,
	}

	// EstimateGas will fail because simulateAndRevert always reverts,
	// but we can extract the gas estimation from the error
	gasLimit, err := v.client.EstimateGas(context.Background(), msg)
	if err != nil {
		// simulateAndRevert always reverts, so we expect an error
		// However, EstimateGas still provides a gas estimate
		// If it's a revert with execution result, that's expected
		// For now, we'll use a fallback approach if estimation fails

		// Try a direct estimation on the target call
		directMsg := ethereum.CallMsg{
			From:  safeAddr, // Simulate call from Safe
			To:    &to,
			Value: value,
			Data:  targetCallData,
		}

		directGas, directErr := v.client.EstimateGas(context.Background(), directMsg)
		if directErr != nil {
			return nil, fmt.Errorf("failed to estimate gas: %w", directErr)
		}

		// Add Safe overhead: approximately 15000 gas for Safe execution logic
		// This includes signature verification, storage operations, and event emissions
		safeTxGas := big.NewInt(int64(directGas + 15000))
		// Add 50% buffer for safety to account for GS010 check requirements
		// GS010 requires: gasleft() >= ((safeTxGas * 64) / 63).max(safeTxGas + 2500) + 500
		safeTxGas = new(big.Int).Mul(safeTxGas, big.NewInt(150))
		safeTxGas = new(big.Int).Div(safeTxGas, big.NewInt(100))
		return safeTxGas, nil
	}

	// If EstimateGas succeeded (shouldn't happen with simulateAndRevert, but handle it)
	safeTxGas := big.NewInt(int64(gasLimit))
	// Add 50% buffer for safety to account for GS010 check requirements
	safeTxGas = new(big.Int).Mul(safeTxGas, big.NewInt(150))
	safeTxGas = new(big.Int).Div(safeTxGas, big.NewInt(100))
	return safeTxGas, nil
}

// ExecuteTransactionBySafeAndSingleSigner executes a Safe transaction with a single EOA signer.
// Migrated from V1 to make V2 fully self-contained.
func (v *ContractInterfaceV2) ExecuteTransactionBySafeAndSingleSigner(
	safeSigner signer.SafeTradingSigner,
	chainID *big.Int,
	safeAddr, to common.Address,
	value *big.Int,
	data []byte,
	operation SafeOperation,
	safeTxGas *big.Int,
) (common.Hash, error) {
	baseGas := big.NewInt(0)
	gasPrice := big.NewInt(0)
	gasToken := common.Address{}
	refundReceiver := common.Address{}

	safeContract, err := v.GetGnosisSafeL2(safeAddr)
	if err != nil {
		return common.Hash{}, err
	}

	nonce, err := safeContract.Nonce(nil)
	if err != nil {
		return common.Hash{}, err
	}

	// Estimate safeTxGas if not set
	if safeTxGas == nil || safeTxGas.Cmp(big.NewInt(0)) == 0 {
		estimatedGas, err := v.EstimateSafeTxGas(safeAddr, to, value, data, operation)
		if err != nil {
			return common.Hash{}, fmt.Errorf("failed to estimate safeTxGas: %w", err)
		}
		safeTxGas = estimatedGas
	}

	// Build typed data for signing
	typedData := BuildSafeTransactionTypedData(chainID, safeAddr, to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)

	// Sign
	signature, err := safeSigner.SignTypedData(typedData)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to sign Safe transaction: %w", err)
	}

	// Verify signature
	safeTxHash, _, err := eip712.TypedDataAndHash(typedData)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to compute typed data hash: %w", err)
	}

	safeL2, err := v.GetGnosisSafeL2(safeAddr)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get GnosisSafeL2 contract: %w", err)
	}

	encodedTxData, err := safeL2.EncodeTransactionData(nil, to, value, data, uint8(operation), safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to encode transaction data: %w", err)
	}

	err = safeL2.CheckSignatures(nil, common.BytesToHash(safeTxHash), encodedTxData, signature)
	if err != nil {
		return common.Hash{}, fmt.Errorf("signature verification failed: %w", err)
	}

	// Execute via txSender — prefer executor's txSender, fall back to safeSigner itself
	txSender := v.executor.txSender
	if txSender == nil {
		txSender = safeSigner
	}

	safeAbi, err := gnosissafe.GnosisSafeL2MetaData.GetAbi()
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to get Safe ABI: %w", err)
	}

	execTxData, err := safeAbi.Pack(
		"execTransaction",
		to, value, data, uint8(operation),
		safeTxGas, baseGas, gasPrice,
		gasToken, refundReceiver, signature,
	)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to pack execTransaction: %w", err)
	}

	txHash, err := txSender.SendEthereumTransaction(safeAddr, execTxData, big.NewInt(0))
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send Safe transaction: %w", err)
	}

	return txHash, nil
}

// ====================================================================================
// Backward Compatibility Methods (migrated from V1 ContractInterface)
// ====================================================================================

// PrintBalanceAndAllowance prints V2 balance and allowance information in a user-friendly format
func (v *ContractInterfaceV2) PrintBalanceAndAllowance(ctx context.Context, address common.Address) error {
	info, err := v.GetBalances(ctx, address)
	if err != nil {
		return err
	}

	fmt.Println("=== V2 Balance and Allowance Status ===")

	// Print pUSD Balance (assuming 6 decimals like USDC)
	fmt.Printf("pUSD Balance: %s pUSD\n", formatUSDC(info.PUSDBalance))
	fmt.Printf("USDC Balance: %s USDC\n", formatUSDC(info.USDCBalance))
	fmt.Printf("USDC.e Balance: %s USDC.e\n\n", formatUSDC(info.USDCEBalance))

	// Print Allowances
	fmt.Println("Allowances:")
	fmt.Printf("  USDC → CollateralOnramp: %s\n", checkmark(info.USDCAllowanceOnramp.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  USDC.e → CollateralOnramp: %s\n", checkmark(info.USDCEAllowanceOnramp.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  pUSD → ExchangeV2: %s\n", checkmark(info.PUSDAllowanceExchangeV2.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  pUSD → NegRiskExchangeV2: %s\n", checkmark(info.PUSDAllowanceNegRiskExchangeV2.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  pUSD → NegRiskAdapter: %s\n", checkmark(info.PUSDAllowanceNegRiskAdapter.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  pUSD → CtfCollateralAdapter: %s\n", checkmark(info.PUSDAllowanceCtfAdapter.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  pUSD → NegRiskCtfCollateralAdapter: %s\n", checkmark(info.PUSDAllowanceNegRiskCtfAdapter.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  pUSD → CollateralOfframp: %s\n", checkmark(info.PUSDAllowanceOfframp.Cmp(big.NewInt(0)) > 0))
	fmt.Printf("  CTF → ExchangeV2: %s\n", checkmark(info.CTFApprovedExchangeV2))
	fmt.Printf("  CTF → NegRiskExchangeV2: %s\n", checkmark(info.CTFApprovedNegRiskExchangeV2))
	fmt.Printf("  CTF → CtfCollateralAdapter: %s\n", checkmark(info.CTFApprovedCtfCollateralAdapter))
	fmt.Printf("  CTF → NegRiskCtfCollateralAdapter: %s\n\n", checkmark(info.CTFApprovedNegRiskCtfCollateralAdapter))

	return nil
}

// DeploySafe deploys a Safe proxy for the given Safe signer
// Note: Safe deployment is the same in V1 and V2 (uses SafeProxyFactory)
func (v *ContractInterfaceV2) DeploySafe(safeSigner signer.SafeTradingSigner) (safeProxy common.Address, txHash common.Hash, err error) {
	zeroAddr := common.Address{}
	paymentToken := zeroAddr
	payment := big.NewInt(0)
	paymentReceiver := zeroAddr

	typedData := BuildCreateProxyTypedData(v.chainID, v.config.SafeProxyFactory, paymentToken, payment, paymentReceiver)
	signatureBytes, err := safeSigner.SignTypedData(typedData)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	r, s, v2, err := ethsig.ConvertSigBytes2RSV(signatureBytes)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}

	createSig := safeproxyfactory.SafeProxyFactorySig{
		R: r,
		S: s,
		V: v2,
	}

	return v.deploySafeWithSig(v.chainID, v.config.SafeProxyFactory, paymentToken, payment, paymentReceiver, createSig, safeSigner)
}

// deploySafeWithSig deploys a Safe with the provided signature
func (v *ContractInterfaceV2) deploySafeWithSig(chainID *big.Int, safeFactory, paymentToken common.Address, payment *big.Int, paymentReceiver common.Address, createSig safeproxyfactory.SafeProxyFactorySig, safeSigner signer.SafeTradingSigner) (safeProxy common.Address, txHash common.Hash, err error) {
	typedData := BuildCreateProxyTypedData(chainID, safeFactory, paymentToken, payment, paymentReceiver)
	typedDataHash, _, err := eip712.TypedDataAndHash(typedData)
	if err != nil {
		return
	}

	// Convert to signature bytes with V normalized to 0/1 for crypto.SigToPub
	vNormalized := ethsig.DenormalizeV(createSig.V)
	sigBytes := ethsig.ConvertRSV2SigBytes(createSig.R, createSig.S, vNormalized)

	pubkey, err := crypto.SigToPub(typedDataHash, sigBytes)
	if err != nil {
		return
	}

	addr := crypto.PubkeyToAddress(*pubkey)
	safeProxy, err = v.GetSafeAddress(addr)
	if err != nil {
		return
	}

	code, err := v.client.CodeAt(context.Background(), safeProxy, nil)
	if err != nil {
		return
	}

	if len(code) != 0 {
		err = fmt.Errorf("already deployed")
		return
	}

	// Use ABI Pack to encode createProxy call (same as V1)
	zeroAddr := common.Address{}
	factoryAbi, err := safeproxyfactory.SafeProxyFactoryMetaData.GetAbi()
	if err != nil {
		return
	}

	createProxyData, err := factoryAbi.Pack("createProxy", zeroAddr, big.NewInt(0), zeroAddr, createSig)
	if err != nil {
		return
	}

	txSender := v.executor.txSender
	if txSender == nil {
		txSender = safeSigner
	}
	txHash, err = txSender.SendEthereumTransaction(v.config.SafeProxyFactory, createProxyData, big.NewInt(0))
	if err != nil {
		return
	}

	return
}

// GetTransactionSender returns the transaction sender used by this contract interface
func (v *ContractInterfaceV2) GetTransactionSender() sender.TransactionSender {
	return v.executor.txSender
}
