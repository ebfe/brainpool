package brainpool_test

import (
	"../brainpool"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func str2big(hex string) *big.Int {
	var x big.Int
	_, ok := x.SetString(hex, 16)
	if !ok {
		panic("FOO")
	}
	return &x
}

// 3*Basepoint for each curve
var testvec3G = []struct {
	curve elliptic.Curve
	x, y  string
}{
	{
		curve: brainpool.P160t1(),
		x:     "C7FB4E367ED789413FC9648CE0E921156F37642B",
		y:     "554BBA4E002E3F5C7CEF7F0BD169CC5979D8FF3D",
	}, {
		curve: brainpool.P160r1(),
		x:     "8A7C28A550682CDA519CE7BC73778EA9AC7812B5",
		y:     "868562A3F2101FAF2FB5EE7A0F366DCBAC9147FE",
	}, {
		curve: brainpool.P192t1(),
		x:     "1092182A330DCDBBAB7BD585E1611B05D197DF5745273FDC",
		y:     "65E8622349AA118D9E46DAB8EDDDE2BCF7765F768C05E708",
	}, {
		curve: brainpool.P192r1(),
		x:     "15372D94937774620BDBFF366D5677D8464866C7B0B20626",
		y:     "240F7E24234C9ECC309F54B7D88002EAF78341AB1D1E4919",
	}, {
		curve: brainpool.P224t1(),
		x:     "347945949FC2A5A3C21D6C34F880545B85F9283FFC900FA0BE1EFC11",
		y:     "545EC6FCDF28122F82BFC658DCE53035ECA6267D49199A0CC00CEE8E",
	}, {
		curve: brainpool.P224r1(),
		x:     "9051DAE686FA68103A478DB398818D048C2042F01F0ECAB577E4598E",
		y:     "BAA97F6F99CABF4A626C056B63F21F793589D36CD5981A3579782900",
	}, {
		curve: brainpool.P256t1(),
		x:     "46B2A45FDD881ABEA0CB4E5FEA19C5A72D399245643B06E0FBE24A5E4058D806",
		y:     "4F88CD8D4BC69ACC7B7032D98460B2C23160441F40562C00BEE2AA7860C19AA8",
	}, {
		curve: brainpool.P256r1(),
		x:     "A8F217B77338F1D4D6624C3AB4F6CC16D2AA843D0C0FCA016B91E2AD25CAE39D",
		y:     "4B49CAFC7DAC26BB0AA2A6850A1B40F5FAC10E4589348FB77E65CC5602B74F9D",
	}, {
		curve: brainpool.P320t1(),
		x:     "847758C1C7338EFAB1B79A22B4446F56C87FAB0070B7858E8ABDBBD94D454E0C340EBB42DCF91633",
		y:     "3D944522B6C1B7D42038E281D4D77AC75C2E0A37E33381C3F0D845CF32D54C39406EE208F7F322C1",
	}, {
		curve: brainpool.P320r1(),
		x:     "C1E31FD7F03708CE169CFD15BE47890EDB83ACDEF8AEF8BA0957FC7AC717C6EFBCE18F0BCF5E73C9",
		y:     "CDB9AECE49778B79F7A6EF2FFA840297F67E4D269AD8A58E8A5F27CE8C5ADA7D9303A9404C589400",
	}, {
		curve: brainpool.P384t1(),
		x:     "3E7E83B88BA8D99A004F1C92EE361648A922F773F96D64B2BB66D1F3C0EEAC30485CFEF216F68B596B8861FBC005EA9",
		y:     "298585E0C24722037F09DD015C2FEFEEC87058D76A07FE43ED52E8641B7248D2C8BABA631D9D68ADC2BD7E748C753C0D",
	}, {
		curve: brainpool.P384r1(),
		x:     "7B63205BF00DDAE73B17452B6A27EBF53DF581348C6949F83EE1B6FCC7463BBE3C11EF6596A3B8897D7CC85B3035F11F",
		y:     "761D3A4A5F8093775521A326BC02BAAF7B2EB481EAD16A5C7B2BD39462363E0373C0EDAEA3B8F59381D7129D48772EB3",
	}, {
		curve: brainpool.P512t1(),
		x:     "6EBD6E634974F138300E1D9024E1132BF53BFDCB1D0142501EFCBBD2A295F70FAC1B86449310AB68D8C7E6AAAFA22A0A4398AEDACDCFADD2CBDD03A56EE4FF0D",
		y:     "2FBE930EC94F50E8031161D73095549C2D39E1085DEDB61DB91F1C931C1A0C1022EFFDDC3F91BDE114E87F77F544EE1AC6DDB5DB1F55FE8406FB7F856FF951B0",
	}, {
		curve: brainpool.P512r1(),
		x:     "8DD87E12B0A4CC436CDD42543F20AFE907C80EF3BC2459309C09CEFD830151BC1F6FB975CEECADE4780AE53E1853D62F56E34ABFA9AC7205D4ABF882CCB8D94",
		y:     "26EF5C6E1DAB71D756FF0067376FA7543D903B4A6334C4BBA0B382E1716D843ACDAB8EB772327B3FEBFCB69C0F37C5F8CCE5BC75D8DE6495CDEAFBA05B02C37",
	},
}

func testDoubleAndAdd(curve elliptic.Curve, x1, y1, ex, ey *big.Int) bool {
	x, y := curve.Double(x1, y1)
	x, y = curve.Add(x, y, x1, y1)
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestDoubleAndAdd(t *testing.T) {
	for i, tc := range testvec3G {
		params := tc.curve.Params()
		Gx, Gy := params.Gx, params.Gy

		Ex := str2big(tc.x)
		Ey := str2big(tc.y)

		if !testDoubleAndAdd(tc.curve, Gx, Gy, Ex, Ey) {
			t.Errorf("%d Add(Double(G), G) != 3G", i)
		}
	}
}

func testScalarBaseMult(curve elliptic.Curve, k, ex, ey *big.Int) bool {
	x, y := curve.ScalarBaseMult(k.Bytes())
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}


func TestScalarBaseMult(t *testing.T) {
	three := big.NewInt(3)
	for i, tc := range testvec3G {
		Ex := str2big(tc.x)
		Ey := str2big(tc.y)

		if !testScalarBaseMult(tc.curve, three, Ex, Ey) {
			t.Errorf("%d ScalarBaseMult(3) != 3G", i)
		}
	}
}

func testScalarMult(curve elliptic.Curve, x1, y1, k, ex, ey *big.Int) bool {
	x, y := curve.ScalarMult(x1, y1, k.Bytes())
	return x.Cmp(ex) == 0 && y.Cmp(ey) == 0
}

func TestScalarMult(t *testing.T) {
	three := big.NewInt(3)
	for i, tc := range testvec3G {
		params := tc.curve.Params()
		Gx, Gy := params.Gx, params.Gy
		Ex := str2big(tc.x)
		Ey := str2big(tc.y)

		if !testScalarMult(tc.curve, Gx, Gy, three, Ex, Ey) {
			t.Errorf("%d ScalarMult(G, 3) != 3G", i)
		}
	}
}


