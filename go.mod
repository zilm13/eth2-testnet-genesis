module github.com/protolambda/eth2-testnet-genesis

go 1.16

require (
	github.com/ethereum/go-ethereum v1.10.2
	github.com/herumi/bls-eth-go-binary v0.0.0-20210208203315-e81c3e745d31
	github.com/pkg/errors v0.9.1
	github.com/protolambda/ask v0.0.5
	github.com/protolambda/zrnt v0.15.1
	github.com/protolambda/ztyp v0.1.4
	github.com/stretchr/testify v1.7.0
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/wealdtech/go-bytesutil v1.1.1
	github.com/wealdtech/go-eth2-types/v2 v2.5.3 // indirect
	github.com/wealdtech/go-eth2-util v1.6.3
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
	gotest.tools v2.2.0+incompatible
)

replace github.com/protolambda/zrnt v0.15.1 => github.com/zilm13/zrnt v0.15.2-0.20210622130830-2b7ba5730584
