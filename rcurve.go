package brainpool

import (
	"crypto/elliptic"
	"math/big"
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

func (curve *rcurve) transform(x, y, z *big.Int) (*big.Int, *big.Int) {
	p := curve.params.P

	zz := new(big.Int).Mul(z, z)
	zz.Mod(zz, p)
	tx := new(big.Int).Mul(x, zz)
	tx.Mod(tx, p)

	zz.Mul(zz, z)
	zz.Mod(zz, p)
	ty := new(big.Int).Mul(y, zz)
	ty.Mod(ty, p)

	return tx, ty
}

func (curve *rcurve) toTwisted(x, y *big.Int) (*big.Int, *big.Int) {
	return curve.transform(x, y, curve.z)
}

func (curve *rcurve) fromTwisted(x, y *big.Int) (*big.Int, *big.Int) {
	return curve.transform(x, y, curve.zinv)
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

