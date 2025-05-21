package circuits

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	tEd "github.com/consensys/gnark/std/algebra/native/twistededwards"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type scalarMulGeneric struct {
	curveID twistededwards.ID
	P       tEd.Point
	R       tEd.Point
	S       frontend.Variable
}

func (circuit *scalarMulGeneric) Define(api frontend.API) error {
	res := ScalarMulGeneric(api, &circuit.P, circuit.S)
	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestScalarMulGeneric(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, validWitness, invalidWitness scalarMulGeneric
	circuit.curveID = twistededwards.BLS12_381_BANDERSNATCH

	// get curve params
	params, err := tEd.GetCurveParams(twistededwards.BLS12_381_BANDERSNATCH)
	assert.NoError(err)

	// create witness
	var p, r tbls12381_bandersnatch.PointAffine
	s, _ := rand.Int(rand.Reader, params.Order)
	p.X.SetBigInt(params.Base[0])
	p.Y.SetBigInt(params.Base[1])
	r.ScalarMultiplication(&p, s)

	validWitness.P.X = p.X
	validWitness.P.Y = p.Y
	validWitness.R.X = r.X
	validWitness.R.Y = r.Y
	validWitness.S = s
	invalidWitness.P.X = r.X
	invalidWitness.P.Y = r.Y
	invalidWitness.R.X = p.X
	invalidWitness.R.Y = p.Y
	invalidWitness.S = s

	// check circuits.
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BLS12_381))

}

type scalarMulFakeGLV struct {
	curveID twistededwards.ID
	P       tEd.Point
	R       tEd.Point
	S       frontend.Variable
}

func (circuit *scalarMulFakeGLV) Define(api frontend.API) error {
	res := ScalarMulFakeGLV(api, &circuit.P, circuit.S)
	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestScalarMulFakeGLV(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, validWitness, invalidWitness scalarMulFakeGLV
	circuit.curveID = twistededwards.BLS12_381_BANDERSNATCH

	// get curve params
	params, err := tEd.GetCurveParams(twistededwards.BLS12_381_BANDERSNATCH)
	assert.NoError(err)

	// create witness
	var p, r tbls12381_bandersnatch.PointAffine
	s, _ := rand.Int(rand.Reader, params.Order)
	p.X.SetBigInt(params.Base[0])
	p.Y.SetBigInt(params.Base[1])
	r.ScalarMultiplication(&p, s)

	validWitness.P.X = p.X
	validWitness.P.Y = p.Y
	validWitness.R.X = r.X
	validWitness.R.Y = r.Y
	validWitness.S = s
	invalidWitness.P.X = r.X
	invalidWitness.P.Y = r.Y
	invalidWitness.R.X = p.X
	invalidWitness.R.Y = p.Y
	invalidWitness.S = s

	// check circuits.
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BLS12_381))

}

type scalarMulGLVAndFakeGLV struct {
	curveID twistededwards.ID
	P       tEd.Point
	R       tEd.Point
	S       frontend.Variable
}

func (circuit *scalarMulGLVAndFakeGLV) Define(api frontend.API) error {
	res := ScalarMulGLVAndFakeGLV(api, &circuit.P, circuit.S)
	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestScalarMulGLVAndFakeGLV(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, validWitness, invalidWitness scalarMulGLVAndFakeGLV
	circuit.curveID = twistededwards.BLS12_381_BANDERSNATCH

	// get curve params
	params, err := tEd.GetCurveParams(twistededwards.BLS12_381_BANDERSNATCH)
	assert.NoError(err)

	// create witness
	var p, r tbls12381_bandersnatch.PointAffine
	s, _ := rand.Int(rand.Reader, params.Order)
	p.X.SetBigInt(params.Base[0])
	p.Y.SetBigInt(params.Base[1])
	r.ScalarMultiplication(&p, s)

	validWitness.P.X = p.X
	validWitness.P.Y = p.Y
	validWitness.R.X = r.X
	validWitness.R.Y = r.Y
	validWitness.S = s
	invalidWitness.P.X = r.X
	invalidWitness.P.Y = r.Y
	invalidWitness.R.X = p.X
	invalidWitness.R.Y = p.Y
	invalidWitness.S = s

	// check circuits.
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BLS12_381))

}

type scalarMulGLVAndFakeGLVLog struct {
	curveID twistededwards.ID
	P       tEd.Point
	R       tEd.Point
	S       frontend.Variable
}

func (circuit *scalarMulGLVAndFakeGLVLog) Define(api frontend.API) error {
	res := ScalarMulGLVAndFakeGLVLog(api, &circuit.P, circuit.S)
	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestScalarMulGLVAndFakeGLVLog(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, validWitness, invalidWitness scalarMulGLVAndFakeGLVLog
	circuit.curveID = twistededwards.BLS12_381_BANDERSNATCH

	// get curve params
	params, err := tEd.GetCurveParams(twistededwards.BLS12_381_BANDERSNATCH)
	assert.NoError(err)

	// create witness
	var p, r tbls12381_bandersnatch.PointAffine
	s, _ := rand.Int(rand.Reader, params.Order)
	p.X.SetBigInt(params.Base[0])
	p.Y.SetBigInt(params.Base[1])
	r.ScalarMultiplication(&p, s)

	validWitness.P.X = p.X
	validWitness.P.Y = p.Y
	validWitness.R.X = r.X
	validWitness.R.Y = r.Y
	validWitness.S = s
	invalidWitness.P.X = r.X
	invalidWitness.P.Y = r.Y
	invalidWitness.R.X = p.X
	invalidWitness.R.Y = p.Y
	invalidWitness.S = s

	// check circuits.
	assert.CheckCircuit(&circuit,
		test.WithValidAssignment(&validWitness),
		test.WithInvalidAssignment(&invalidWitness),
		test.WithCurves(ecc.BLS12_381))

}
