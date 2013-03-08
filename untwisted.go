package brainpool

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

type bpcurve struct {
	twisted elliptic.Curve
	z       *big.Int
	zinv    *big.Int
}

func (curve *bpcurve) toTwisted(x, y *big.Int) (*big.Int, *big.Int) {
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

func (curve *bpcurve) fromTwisted(x, y *big.Int) (*big.Int, *big.Int) {
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

func (curve *bpcurve) Params() *elliptic.CurveParams {
	// FIXME: crypto/elliptic assumes A=-3 so we can't give the proper
	// params :/
	params := *curve.twisted.Params()
	params.B = nil
	params.Gx = nil
	params.Gy = nil
	return &params
}

func (curve *bpcurve) IsOnCurve(x, y *big.Int) bool {
	return curve.twisted.IsOnCurve(curve.toTwisted(x, y))
}

func (curve *bpcurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	tx1, ty1 := curve.toTwisted(x1, y1)
	tx2, ty2 := curve.toTwisted(x2, y2)
	return curve.fromTwisted(curve.twisted.Add(tx1, ty1, tx2, ty2))
}

func (curve *bpcurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return curve.fromTwisted(curve.twisted.Double(curve.toTwisted(x1, y1)))
}

func (curve *bpcurve) ScalarMult(x1, y1 *big.Int, scalar []byte) (x, y *big.Int) {
	tx1, ty1 := curve.toTwisted(x1, y1)
	return curve.fromTwisted(curve.twisted.ScalarMult(tx1, ty1, scalar))
}

func (curve *bpcurve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	return curve.fromTwisted(curve.twisted.ScalarBaseMult(scalar))
}

var (
	onceUntwisted sync.Once

	p160r1 bpcurve
	p192r1 bpcurve
	p224r1 bpcurve
	p256r1 bpcurve
	p320r1 bpcurve
	p384r1 bpcurve
	p512r1 bpcurve
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
	p160r1.twisted = P160t1()
	p160r1.z, _ = new(big.Int).SetString("24DBFF5DEC9B986BBFE5295A29BFBAE45E0F5D0B", 16)
	p160r1.zinv = new(big.Int).ModInverse(p160r1.z, p160r1.twisted.Params().P)
}

func initP192r1() {
	p192r1.twisted = P192t1()
	p192r1.z, _ = new(big.Int).SetString("1B6F5CC8DB4DC7AF19458A9CB80DC2295E5EB9C3732104CB", 16)
	p192r1.zinv = new(big.Int).ModInverse(p192r1.z, p192r1.twisted.Params().P)
}

func initP224r1() {
	p224r1.twisted = P224t1()
	p224r1.z, _ = new(big.Int).SetString("2DF271E14427A346910CF7A2E6CFA7B3F484E5C2CCE1C8B730E28B3F", 16)
	p224r1.zinv = new(big.Int).ModInverse(p224r1.z, p224r1.twisted.Params().P)
}

func initP256r1() {
	p256r1.twisted = P256t1()
	p256r1.z, _ = new(big.Int).SetString("3E2D4BD9597B58639AE7AA669CAB9837CF5CF20A2C852D10F655668DFC150EF0", 16)
	p256r1.zinv = new(big.Int).ModInverse(p256r1.z, p256r1.twisted.Params().P)
}

func initP320r1() {
	p320r1.twisted = P320t1()
	p320r1.z, _ = new(big.Int).SetString("15F75CAF668077F7E85B42EB01F0A81FF56ECD6191D55CB82B7D861458A18FEFC3E5AB7496F3C7B1", 16)
	p320r1.zinv = new(big.Int).ModInverse(p320r1.z, p320r1.twisted.Params().P)
}

func initP384r1() {
	p384r1.twisted = P384t1()
	p384r1.z, _ = new(big.Int).SetString("41DFE8DD399331F7166A66076734A89CD0D2BCDB7D068E44E1F378F41ECBAE97D2D63DBC87BCCDDCCC5DA39E8589291C", 16)
	p384r1.zinv = new(big.Int).ModInverse(p384r1.z, p384r1.twisted.Params().P)
}

func initP512r1() {
	p512r1.twisted = P512t1()
	p512r1.z, _ = new(big.Int).SetString("12EE58E6764838B69782136F0F2D3BA06E27695716054092E60A80BEDB212B64E585D90BCE13761F85C3F1D2A64E3BE8FEA2220F01EBA5EEB0F35DBD29D922AB", 16)
	p512r1.zinv = new(big.Int).ModInverse(p512r1.z, p512r1.twisted.Params().P)
}

func P160r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p160r1
}

func P192r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p192r1
}

func P224r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p224r1
}

func P256r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p256r1
}

func P320r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p320r1
}

func P384r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p384r1
}

func P512r1() elliptic.Curve {
	onceUntwisted.Do(inituntwisted)
	return &p512r1
}
