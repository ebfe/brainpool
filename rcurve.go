package brainpool

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

type rcurve struct {
	twisted elliptic.Curve
	params  elliptic.CurveParams
	z       *big.Int
	zinv    *big.Int
}

func newrcurve(twisted elliptic.Curve, gx, gy, z *big.Int) *rcurve {
	var curve rcurve

	curve.twisted = twisted
	curve.params = *twisted.Params()
	curve.params.B = nil // FIXME: crypto/elliptic assumes A=-3
	curve.params.Gx = gx
	curve.params.Gy = gy
	curve.z = z
	curve.zinv = new(big.Int).ModInverse(z, curve.params.P)

	return &curve
}

func (curve *rcurve) toTwisted(x, y *big.Int) (*big.Int, *big.Int) {
	p := curve.twisted.Params().P

	two := big.NewInt(2)
	three := big.NewInt(3)

	t := new(big.Int).Exp(curve.z, two, p)
	tx := new(big.Int).Mul(x, t)
	tx.Mod(tx, p)

	t.Exp(curve.z, three, p)
	ty := new(big.Int).Mul(y, t)
	ty.Mod(ty, p)

	return tx, ty
}

func (curve *rcurve) fromTwisted(x, y *big.Int) (*big.Int, *big.Int) {
	p := curve.twisted.Params().P

	two := big.NewInt(2)
	three := big.NewInt(3)

	t := new(big.Int).Exp(curve.zinv, two, p)
	tx := new(big.Int).Mul(x, t)
	tx.Mod(tx, p)

	t.Exp(curve.zinv, three, p)
	ty := new(big.Int).Mul(y, t)
	ty.Mod(ty, p)

	return tx, ty
}

func (curve *rcurve) Params() *elliptic.CurveParams {
	return &curve.params
}

func (curve *rcurve) IsOnCurve(x, y *big.Int) bool {
	return curve.twisted.IsOnCurve(curve.toTwisted(x, y))
}

func (curve *rcurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	tx1, ty1 := curve.toTwisted(x1, y1)
	tx2, ty2 := curve.toTwisted(x2, y2)
	return curve.fromTwisted(curve.twisted.Add(tx1, ty1, tx2, ty2))
}

func (curve *rcurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return curve.fromTwisted(curve.twisted.Double(curve.toTwisted(x1, y1)))
}

func (curve *rcurve) ScalarMult(x1, y1 *big.Int, scalar []byte) (x, y *big.Int) {
	tx1, ty1 := curve.toTwisted(x1, y1)
	return curve.fromTwisted(curve.twisted.ScalarMult(tx1, ty1, scalar))
}

func (curve *rcurve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	return curve.fromTwisted(curve.twisted.ScalarBaseMult(scalar))
}

var (
	onceUntwisted sync.Once

	p160r1 *rcurve
	p192r1 *rcurve
	p224r1 *rcurve
	p256r1 *rcurve
	p320r1 *rcurve
	p384r1 *rcurve
	p512r1 *rcurve
)

func inituntwisted() {
	initP160r1()
	initP192r1()
	initP224r1()
	initP256r1()
	initP320r1()
	initP384r1()
	initP512r1()
}

func initP160r1() {
	twisted := P160t1()
	gx, _ := new(big.Int).SetString("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", 16)
	gy, _ := new(big.Int).SetString("1667CB477A1A8EC338F94741669C976316DA6321", 16)
	z, _ := new(big.Int).SetString("24DBFF5DEC9B986BBFE5295A29BFBAE45E0F5D0B", 16)
	p160r1 = newrcurve(twisted, gx, gy, z)
}

func initP192r1() {
	twisted := P192t1()
	gx, _ := new(big.Int).SetString("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6", 16)
	gy, _ := new(big.Int).SetString("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F", 16)
	z, _ := new(big.Int).SetString("1B6F5CC8DB4DC7AF19458A9CB80DC2295E5EB9C3732104CB", 16)
	p192r1 = newrcurve(twisted, gx, gy, z)
}

func initP224r1() {
	twisted := P224t1()
	gx, _ := new(big.Int).SetString("D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D", 16)
	gy, _ := new(big.Int).SetString("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD", 16)
	z, _ := new(big.Int).SetString("2DF271E14427A346910CF7A2E6CFA7B3F484E5C2CCE1C8B730E28B3F", 16)
	p224r1 = newrcurve(twisted, gx, gy, z)
}

func initP256r1() {
	twisted := P256t1()
	gx, _ := new(big.Int).SetString("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16)
	gy, _ := new(big.Int).SetString("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16)
	z, _ := new(big.Int).SetString("3E2D4BD9597B58639AE7AA669CAB9837CF5CF20A2C852D10F655668DFC150EF0", 16)
	p256r1 = newrcurve(twisted, gx, gy, z)
}

func initP320r1() {
	twisted := P320t1()
	gx, _ := new(big.Int).SetString("43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611", 16)
	gy, _ := new(big.Int).SetString("14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1", 16)
	z, _ := new(big.Int).SetString("15F75CAF668077F7E85B42EB01F0A81FF56ECD6191D55CB82B7D861458A18FEFC3E5AB7496F3C7B1", 16)
	p320r1 = newrcurve(twisted, gx, gy, z)
}

func initP384r1() {
	twisted := P384t1()
	gx, _ := new(big.Int).SetString("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16)
	gy, _ := new(big.Int).SetString("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16)
	z, _ := new(big.Int).SetString("41DFE8DD399331F7166A66076734A89CD0D2BCDB7D068E44E1F378F41ECBAE97D2D63DBC87BCCDDCCC5DA39E8589291C", 16)
	p384r1 = newrcurve(twisted, gx, gy, z)
}

func initP512r1() {
	twisted := P512t1()
	gx, _ := new(big.Int).SetString("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16)
	gy, _ := new(big.Int).SetString("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16)
	z, _ := new(big.Int).SetString("12EE58E6764838B69782136F0F2D3BA06E27695716054092E60A80BEDB212B64E585D90BCE13761F85C3F1D2A64E3BE8FEA2220F01EBA5EEB0F35DBD29D922AB", 16)
	p512r1 = newrcurve(twisted, gx, gy, z)
}

func P160r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p160r1
}

func P192r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p192r1
}

func P224r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p224r1
}

func P256r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p256r1
}

func P320r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p320r1
}

func P384r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p384r1
}

func P512r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return p512r1
}
