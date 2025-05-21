package circuits

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	tEd "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/selector"
)

// ScalarMulGeneric uses a 2-bit windowed double-and-add algorithm to compute
// the scalar multilication [s]p on the Bandersnatch curve in twisted Edwards
// form.
func ScalarMulGeneric(api frontend.API, p *tEd.Point, s frontend.Variable) *tEd.Point {
	// get edwards curve curve
	curve, err := tEd.NewEdCurve(api, twistededwards.BLS12_381_BANDERSNATCH)
	if err != nil {
		return nil
	}

	A := curve.Double(*p)
	B := curve.Add(A, *p)

	// unpack the scalar
	b := api.ToBinary(s)
	n := len(b) - 1

	res := tEd.Point{}
	tmp := tEd.Point{}
	res.X = api.Lookup2(b[n], b[n-1], 0, A.X, p.X, B.X)
	res.Y = api.Lookup2(b[n], b[n-1], 1, A.Y, p.Y, B.Y)

	for i := n - 2; i >= 1; i -= 2 {
		res = curve.Double(res)
		res = curve.Double(res)
		tmp.X = api.Lookup2(b[i], b[i-1], 0, A.X, p.X, B.X)
		tmp.Y = api.Lookup2(b[i], b[i-1], 1, A.Y, p.Y, B.Y)
		res = curve.Add(res, tmp)
	}

	if n%2 == 0 {
		res = curve.Double(res)
		tmp = curve.Add(res, *p)
		res.X = api.Select(b[0], tmp.X, res.X)
		res.Y = api.Select(b[0], tmp.Y, res.Y)
	}

	return &tEd.Point{X: res.X, Y: res.Y}
}

// ScalarMulFakeGLV computes the scalar multilication [s]p=q on the Bandersnatch
// curve in twisted Edwards form as:
//
//	[s1]p + [s2]q = (0,1) with s1 + s2 * s = 0 mod r and |s1|,|s2| < sqrt(r)
func ScalarMulFakeGLV(api frontend.API, p *tEd.Point, scalar frontend.Variable) *tEd.Point {
	// get edwards curve curve
	curve, err := tEd.NewEdCurve(api, twistededwards.BLS12_381_BANDERSNATCH)
	if err != nil {
		return nil
	}
	params := curve.Params()

	// the hints allow to decompose the scalar s into s1 and s2 such that
	// s1 + s * s2 == 0 mod Order,
	s, err := api.NewHint(halfGCD, 4, scalar, params.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	s1, s2, bit, k := s[0], s[1], s[2], s[3]

	// check that s1 + s2 * s == k*Order
	_s2 := api.Mul(s2, scalar)
	_k := api.Mul(k, params.Order)
	lhs := api.Select(bit, s1, api.Add(s1, _s2))
	rhs := api.Select(bit, api.Add(_k, _s2), _k)
	api.AssertIsEqual(lhs, rhs)

	n := (params.Order.BitLen() + 1) / 2
	b1 := api.ToBinary(s1, n)
	b2 := api.ToBinary(s2, n)

	var res, p2, p3, tmp tEd.Point
	q, err := api.NewHint(scalarMulHint, 2, p.X, p.Y, scalar, params.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	p2.X = api.Select(bit, api.Neg(q[0]), q[0])
	p2.Y = q[1]

	p3 = curve.Add(*p, p2)

	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, p.X, p2.X, p3.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, p.Y, p2.Y, p3.Y)

	for i := n - 2; i >= 0; i-- {
		res = curve.Double(res)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, p.X, p2.X, p3.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, p.Y, p2.Y, p3.Y)
		res = curve.Add(res, tmp)
	}

	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	return &tEd.Point{X: q[0], Y: q[1]}
}

// phi endomorphism √-2 ∈ 𝒪₋₈
// (x,y) → λ × (x,y) s.t. λ² = -2 mod Order
func phi(api frontend.API, p *tEd.Point) *tEd.Point {
	// get edwards curve curve
	curve, err := tEd.NewEdCurve(api, twistededwards.BLS12_381_BANDERSNATCH)
	if err != nil {
		return nil
	}
	endo := curve.Endo()

	xy := api.Mul(p.X, p.Y)
	yy := api.Mul(p.Y, p.Y)
	f := api.Sub(1, yy)
	f = api.Mul(f, endo.Endo[1])
	g := api.Add(yy, endo.Endo[0])
	g = api.Mul(g, endo.Endo[0])
	h := api.Sub(yy, endo.Endo[0])

	return &tEd.Point{
		X: api.DivUnchecked(f, xy),
		Y: api.DivUnchecked(g, h),
	}
}

// ScalarMulGLVAndFakeGLV computes the scalar multilication [s]p=q on the Bandersnatch
// curve in twisted Edwards form as:
//
// [u1]p + [u2]φ(p) + [v1]q + [v2]φ(q) = (0,1)
// with u1+λ*u2 + s*(v1+λ*v2) == 0 mod r and u1, u2, v1, v2 < c*sqrt(sqrt(r)).
//
// This method uses a multiplexer for the 16-to-1 lookup table.
func ScalarMulGLVAndFakeGLV(api frontend.API, p *tEd.Point, scalar frontend.Variable) *tEd.Point {
	// get edwards curve curve
	curve, err := tEd.NewEdCurve(api, twistededwards.BLS12_381_BANDERSNATCH)
	if err != nil {
		return nil
	}
	params := curve.Params()
	endo := curve.Endo()

	// the hints allow to decompose the scalar s into u1, u2, v1 and v2 such that
	// u1+λ*u2 + scalar * (v1+λ*v2) == 0 mod Order.
	s, err := api.NewHint(halfGCDZZ2, 4, scalar, endo.Lambda)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	u1, u2, v1, v2 := s[0], s[1], s[2], s[3]

	// check the decomposition using non-native arithmetic
	checkHalfGCDZZ2(api, scalar, endo.Lambda)

	// ZZ2 integers real and imaginary parts can be negative. So we
	// return the absolute value in the hint and negate the corresponding
	// points here when needed.
	signs, err := api.NewHint(halfGCDZZ2Signs, 4, scalar, endo.Lambda)
	if err != nil {
		panic(fmt.Sprintf("halfGCDSigns hint: %v", err))
	}
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// |u1, u2, v1, v2|∞ ≤ 256 · √√2 · √√r
	n := params.Order.BitLen()/4 + 9
	b1 := api.ToBinary(u1, n)
	b2 := api.ToBinary(u2, n)
	b3 := api.ToBinary(v1, n)
	b4 := api.ToBinary(v2, n)

	q, err := api.NewHint(scalarMulHint, 2, p.X, p.Y, scalar, params.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	// [s]P = Q is equivalent to:
	// [u1]P + [u2]φ(P) + [v1]Q + [v2]φ(Q) = (0,1)
	//
	// Pre-compute:
	// 		T0 = (0,1)
	// 		T1 = P1
	// 		T2 = Q
	// 		T3 = φ(P1)
	// 		T4 = φ(Q)
	// 		T5 = P1 + Q
	// 		T6 = P1 + φ(P1)
	// 		T7 = P1 + φ(Q)
	// 		T8 = Q + φ(P1)
	// 		T9 = Q + φ(Q)
	// 		T10 = φ(P1) + φ(Q)
	// 		T11 = P1 + Q + φ(P1)
	// 		T12 = P1 + Q + φ(Q)
	// 		T13 = P1 + φ(P1) + φ(Q)
	// 		T14 = Q + φ(P1) + φ(Q)
	// 		T15 = P1 + Q + φ(P1) + φ(Q)

	var t [16]tEd.Point
	var temp tEd.Point
	t[0].X = 0
	t[0].Y = 1
	t[1].X = api.Select(isNegu1, api.Neg(p.X), p.X)
	t[1].Y = p.Y
	t[2].X = api.Select(isNegv1, api.Neg(q[0]), q[0])
	t[2].Y = q[1]
	t[3] = *phi(api, p)
	t[3].X = api.Select(isNegu2, api.Neg(t[3].X), t[3].X)
	t[4] = *phi(api, &tEd.Point{X: q[0], Y: q[1]})
	t[4].X = api.Select(isNegv2, api.Neg(t[4].X), t[4].X)
	t[5] = curve.Add(t[1], t[2])
	t[6] = curve.Add(t[1], t[3])
	t[7] = curve.Add(t[1], t[4])
	t[8] = curve.Add(t[2], t[3])
	t[9] = curve.Add(t[2], t[4])
	t[10] = curve.Add(t[3], t[4])
	t[11] = curve.Add(t[5], t[3])
	t[12] = curve.Add(t[5], t[4])
	t[13] = curve.Add(t[6], t[4])
	t[14] = curve.Add(t[8], t[4])
	t[15] = curve.Add(t[7], t[8])

	flag := api.Add(
		b1[n-1],
		api.Mul(b2[n-1], 2),
		api.Mul(b3[n-1], 4),
		api.Mul(b4[n-1], 8),
	)

	res := tEd.Point{
		X: selector.Mux(api, flag,
			t[0].X, t[1].X, t[3].X, t[6].X, t[2].X, t[5].X, t[8].X, t[11].X,
			t[4].X, t[7].X, t[10].X, t[13].X, t[9].X, t[12].X, t[14].X, t[15].X,
		),
		Y: selector.Mux(api, flag,
			t[0].Y, t[1].Y, t[3].Y, t[6].Y, t[2].Y, t[5].Y, t[8].Y, t[11].Y,
			t[4].Y, t[7].Y, t[10].Y, t[13].Y, t[9].Y, t[12].Y, t[14].Y, t[15].Y,
		),
	}

	for i := n - 2; i >= 0; i-- {
		flag = api.Add(
			b1[i],
			api.Mul(b2[i], 2),
			api.Mul(b3[i], 4),
			api.Mul(b4[i], 8),
		)

		res = curve.Double(res)

		temp = tEd.Point{
			X: selector.Mux(api, flag,
				t[0].X, t[1].X, t[3].X, t[6].X, t[2].X, t[5].X, t[8].X, t[11].X,
				t[4].X, t[7].X, t[10].X, t[13].X, t[9].X, t[12].X, t[14].X, t[15].X,
			),
			Y: selector.Mux(api, flag,
				t[0].Y, t[1].Y, t[3].Y, t[6].Y, t[2].Y, t[5].Y, t[8].Y, t[11].Y,
				t[4].Y, t[7].Y, t[10].Y, t[13].Y, t[9].Y, t[12].Y, t[14].Y, t[15].Y,
			),
		}
		res = curve.Add(res, temp)
	}

	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	return &tEd.Point{X: q[0], Y: q[1]}
}

// ScalarMulGLVAndFakeGLVLog computes the scalar multilication [s]p=q on the Bandersnatch
// curve in twisted Edwards form as:
//
// [u1]p + [u2]φ(p) + [v1]q + [v2]φ(q) = (0,1)
// with u1+λ*u2 + s*(v1+λ*v2) == 0 mod r and u1, u2, v1, v2 < c*sqrt(sqrt(r)).
//
// This method uses a logup lookup argument for the 16-to-1 lookup table.
func ScalarMulGLVAndFakeGLVLog(api frontend.API, p *tEd.Point, scalar frontend.Variable) *tEd.Point {
	// get edwards curve curve
	curve, err := tEd.NewEdCurve(api, twistededwards.BLS12_381_BANDERSNATCH)
	if err != nil {
		return nil
	}
	params := curve.Params()
	endo := curve.Endo()

	// the hints allow to decompose the scalar s into u1, u2, v1 and v2 such that
	// u1+λ*u2 + scalar * (v1+λ*v2) == 0 mod Order.
	s, err := api.NewHint(halfGCDZZ2, 4, scalar, endo.Lambda)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}
	u1, u2, v1, v2 := s[0], s[1], s[2], s[3]

	// check the decomposition using non-native arithmetic
	checkHalfGCDZZ2(api, scalar, endo.Lambda)

	// ZZ2 integers real and imaginary parts can be negative. So we
	// return the absolute value in the hint and negate the corresponding
	// points here when needed.
	signs, err := api.NewHint(halfGCDZZ2Signs, 4, scalar, endo.Lambda)
	if err != nil {
		panic(fmt.Sprintf("halfGCDSigns hint: %v", err))
	}
	isNegu1, isNegu2, isNegv1, isNegv2 := signs[0], signs[1], signs[2], signs[3]

	// |u1, u2, v1, v2|∞ ≤ 256 · √√2 · √√r
	n := params.Order.BitLen()/4 + 9
	b1 := api.ToBinary(u1, n)
	b2 := api.ToBinary(u2, n)
	b3 := api.ToBinary(v1, n)
	b4 := api.ToBinary(v2, n)

	q, err := api.NewHint(scalarMulHint, 2, p.X, p.Y, scalar, params.Order)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	// [s]P = Q is equivalent to:
	// [u1]P + [u2]φ(P) + [v1]Q + [v2]φ(Q) = (0,1)
	//
	// Pre-compute:
	// 		T0 = (0,1)
	// 		T1 = P1
	// 		T2 = Q
	// 		T3 = φ(P1)
	// 		T4 = φ(Q)
	// 		T5 = P1 + Q
	// 		T6 = P1 + φ(P1)
	// 		T7 = P1 + φ(Q)
	// 		T8 = Q + φ(P1)
	// 		T9 = Q + φ(Q)
	// 		T10 = φ(P1) + φ(Q)
	// 		T11 = P1 + Q + φ(P1)
	// 		T12 = P1 + Q + φ(Q)
	// 		T13 = P1 + φ(P1) + φ(Q)
	// 		T14 = Q + φ(P1) + φ(Q)
	// 		T15 = P1 + Q + φ(P1) + φ(Q)

	var t [16]tEd.Point
	var temp tEd.Point
	t[0].X = 0
	t[0].Y = 1
	t[1].X = api.Select(isNegu1, api.Neg(p.X), p.X)
	t[1].Y = p.Y
	t[2].X = api.Select(isNegv1, api.Neg(q[0]), q[0])
	t[2].Y = q[1]
	t[3] = *phi(api, p)
	t[3].X = api.Select(isNegu2, api.Neg(t[3].X), t[3].X)
	t[4] = *phi(api, &tEd.Point{X: q[0], Y: q[1]})
	t[4].X = api.Select(isNegv2, api.Neg(t[4].X), t[4].X)
	t[5] = curve.Add(t[1], t[2])
	t[6] = curve.Add(t[1], t[3])
	t[7] = curve.Add(t[1], t[4])
	t[8] = curve.Add(t[2], t[3])
	t[9] = curve.Add(t[2], t[4])
	t[10] = curve.Add(t[3], t[4])
	t[11] = curve.Add(t[5], t[3])
	t[12] = curve.Add(t[5], t[4])
	t[13] = curve.Add(t[6], t[4])
	t[14] = curve.Add(t[8], t[4])
	t[15] = curve.Add(t[7], t[8])

	tblX := logderivlookup.New(api)
	tblY := logderivlookup.New(api)
	tblX.Insert(t[0].X)
	tblX.Insert(t[1].X)
	tblX.Insert(t[3].X)
	tblX.Insert(t[6].X)
	tblX.Insert(t[2].X)
	tblX.Insert(t[5].X)
	tblX.Insert(t[8].X)
	tblX.Insert(t[11].X)
	tblX.Insert(t[4].X)
	tblX.Insert(t[7].X)
	tblX.Insert(t[10].X)
	tblX.Insert(t[13].X)
	tblX.Insert(t[9].X)
	tblX.Insert(t[12].X)
	tblX.Insert(t[14].X)
	tblX.Insert(t[15].X)

	tblY.Insert(t[0].Y)
	tblY.Insert(t[1].Y)
	tblY.Insert(t[3].Y)
	tblY.Insert(t[6].Y)
	tblY.Insert(t[2].Y)
	tblY.Insert(t[5].Y)
	tblY.Insert(t[8].Y)
	tblY.Insert(t[11].Y)
	tblY.Insert(t[4].Y)
	tblY.Insert(t[7].Y)
	tblY.Insert(t[10].Y)
	tblY.Insert(t[13].Y)
	tblY.Insert(t[9].Y)
	tblY.Insert(t[12].Y)
	tblY.Insert(t[14].Y)
	tblY.Insert(t[15].Y)

	flag := api.Add(
		b1[n-1],
		api.Mul(b2[n-1], 2),
		api.Mul(b3[n-1], 4),
		api.Mul(b4[n-1], 8),
	)

	res := tEd.Point{
		X: tblX.Lookup(flag)[0],
		Y: tblY.Lookup(flag)[0],
	}

	for i := n - 2; i >= 0; i-- {
		flag = api.Add(
			b1[i],
			api.Mul(b2[i], 2),
			api.Mul(b3[i], 4),
			api.Mul(b4[i], 8),
		)

		res = curve.Double(res)

		temp = tEd.Point{
			X: tblX.Lookup(flag)[0],
			Y: tblY.Lookup(flag)[0],
		}
		res = curve.Add(res, temp)
	}

	api.AssertIsEqual(res.X, 0)
	api.AssertIsEqual(res.Y, 1)

	return &tEd.Point{X: q[0], Y: q[1]}
}
