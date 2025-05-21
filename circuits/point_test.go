package circuits

import (
	"crypto/rand"
	"testing"

	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	tbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	tbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
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
	res := ScalarMulGeneric(api, &circuit.P, circuit.S, circuit.curveID)
	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestScalarMulGeneric1(t *testing.T) {
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

func TestScalarMulGeneric2(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, validWitness, invalidWitness scalarMulGeneric
	circuit.curveID = twistededwards.BLS12_381

	// get curve params
	params, err := tEd.GetCurveParams(twistededwards.BLS12_381)
	assert.NoError(err)

	// create witness
	var p, r tbls12381.PointAffine
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
	res := ScalarMulFakeGLV(api, &circuit.P, circuit.S, circuit.curveID)
	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestScalarMulFakeGLV1(t *testing.T) {
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

func TestScalarMulFakeGLV2(t *testing.T) {
	assert := test.NewAssert(t)
	var circuit, validWitness, invalidWitness scalarMulFakeGLV
	circuit.curveID = twistededwards.BLS12_381

	// get curve params
	params, err := tEd.GetCurveParams(twistededwards.BLS12_381)
	assert.NoError(err)

	// create witness
	var p, r tbls12381.PointAffine
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

// bench
func BenchmarkScalarMulGenericJubjubSCS(b *testing.B) {
	c := scalarMulGeneric{curveID: twistededwards.BLS12_381}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Jubjub generic (scs): ", p.NbConstraints())
}

func BenchmarkScalarMulGenericJubjubR1CS(b *testing.B) {
	c := scalarMulGeneric{curveID: twistededwards.BLS12_381}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Jubjub generic (r1cs): ", p.NbConstraints())
}

func BenchmarkScalarMulFakeGLVJubjubSCS(b *testing.B) {
	c := scalarMulFakeGLV{curveID: twistededwards.BLS12_381}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Jubjub 2D hinted GLV (scs): ", p.NbConstraints())
}

func BenchmarkScalarMulFakeGLVJubjubR1CS(b *testing.B) {
	c := scalarMulFakeGLV{curveID: twistededwards.BLS12_381}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Jubjub 2D hinted GLV (r1cs): ", p.NbConstraints())
}

func BenchmarkScalarMulGenericBandersnatchSCS(b *testing.B) {
	c := scalarMulGeneric{curveID: twistededwards.BLS12_381}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch generic (scs): ", p.NbConstraints())
}

func BenchmarkScalarMulGenericBandersnatchR1CS(b *testing.B) {
	c := scalarMulGeneric{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch generic (r1cs): ", p.NbConstraints())
}

func BenchmarkScalarMulFakeGLVBandersnatchSCS(b *testing.B) {
	c := scalarMulFakeGLV{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch 2D hinted GLV (scs): ", p.NbConstraints())
}

func BenchmarkScalarMulFakeGLVBandersnatchR1CS(b *testing.B) {
	c := scalarMulFakeGLV{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch 2D hinted (r1cs): ", p.NbConstraints())
}

func BenchmarkScalarMulGLVAndFakeGLVBandersnatchSCS(b *testing.B) {
	c := scalarMulGLVAndFakeGLV{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch 4D hinted GLV (scs): ", p.NbConstraints())
}

func BenchmarkScalarMulGLVAndFakeGLVBandersnatchR1CS(b *testing.B) {
	c := scalarMulGLVAndFakeGLV{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch 4D hinted (r1cs): ", p.NbConstraints())
}

func BenchmarkScalarMulGLVAndFakeGLVLogupBandersnatchSCS(b *testing.B) {
	c := scalarMulGLVAndFakeGLVLog{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch 4D hinted GLV with logup (scs): ", p.NbConstraints())
}

func BenchmarkScalarMulGLVAndFakeGLVLogupBandersnatchR1CS(b *testing.B) {
	c := scalarMulGLVAndFakeGLVLog{curveID: twistededwards.BLS12_381_BANDERSNATCH}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("Bandersnatch 4D hinted with logup (r1cs): ", p.NbConstraints())
}
