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
		curve := curve.(*bpcurve)

		tx, ty := curve.toTwisted(curve.gx, curve.gy)

		if tx.Cmp(curve.twisted.Params().Gx) != 0 ||
		   ty.Cmp(curve.twisted.Params().Gy) != 0 {
			   t.Errorf("%d toTwisted(Gx,Gy) doesn't match twisted curves basepoint", i)
		}

		xx, yy := curve.fromTwisted(tx, ty)
		if curve.gx.Cmp(xx) != 0 ||
		   curve.gy.Cmp(yy) != 0 {
			   t.Errorf("%d fromTwisted(toTwisted(x,y)) != x,y", i)
		}
	}
}
