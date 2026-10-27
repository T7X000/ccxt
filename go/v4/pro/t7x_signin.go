package ccxtpro

// Hand-written, not generated: the Go transpiler only emits blocking wrappers for
// fetch*/create*/edit*/cancel*/... methods, so signIn only gets SignInAsync.

// SignIn signs in with the api key and stores the session token, see t7x#signIn
func (this *T7x) SignIn(params ...any) (map[string]any, error) {
	r := <-this.SignInAsync(params...)
	if r.Err != nil {
		return nil, r.Err
	}
	res, _ := r.Value.(map[string]any)
	return res, nil
}
