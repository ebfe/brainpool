package brainpool

import (
	"crypto/elliptic"
	"testing"
)

var untwistedCurves = []elliptic.Curve{
	P160r1(),
	P192r1(),
	P224r1(),
	P256r1(),
	P320r1(),
	P384r1(),
	P512r1(),
}

func TestTransformBasepoint(t *testing.T) {
	for i, curve := range untwistedCurves {
		curve := curve.(*rcurve)
		params := curve.Params()

		gx, gy := params.Gx, params.Gy
		tx, ty := curve.toTwisted(gx, gy)

		if tx.Cmp(curve.twisted.Params().Gx) != 0 ||
		   ty.Cmp(curve.twisted.Params().Gy) != 0 {
			   t.Errorf("%d toTwisted(Gx,Gy) doesn't match twisted curves basepoint", i)
		}

		xx, yy := curve.fromTwisted(tx, ty)
		if gx.Cmp(xx) != 0 ||
		   gy.Cmp(yy) != 0 {
			   t.Errorf("%d fromTwisted(toTwisted(x,y)) != x,y", i)
		}
	}
}
