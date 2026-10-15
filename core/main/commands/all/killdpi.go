package all

import (
	"fmt"

	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/proxy/killdpi"
)

var cmdKillDPIKeygen = &base.Command{
	UsageLine: `{{.Exec}} killdpi-keygen`,
	Short:     `Generate a KILLDPI server key pair and a client UUID`,
	Long: `
Generate the X25519 static key pair used by the KILLDPI protocol together with a
fresh client UUID.

  "privateKey" goes into the server (inbound) settings,
  "publicKey"  goes into every client (outbound) settings.
`,
	Run: func(cmd *base.Command, args []string) {
		priv, pub, err := killdpi.GenerateKeyPair()
		if err != nil {
			base.Fatalf("failed to generate key pair: %v", err)
		}
		u := uuid.New()
		fmt.Printf("PrivateKey: %s\nPublicKey:  %s\nUUID:       %s\n", priv, pub, u.String())
	},
}
