use polynomial_ring::Polynomial;

#[test]
fn default_parameters_use_the_verified_tuple() {
    let params = module_lwe::utils::Parameters::default();
    assert_eq!((params.n, params.q, params.omega), (512, 12289, 10302));
    assert_eq!(params.f.coeffs().len(), 513);
    assert_eq!(params.f.coeffs()[0], 1);
    assert_eq!(params.f.coeffs()[512], 1);
    assert!(params.f.coeffs()[1..512].iter().all(|&x| x == 0));
}

#[test]
fn module_vector_multiplication_accepts_trimmed_and_zero_polynomials() {
    let params = module_lwe::utils::Parameters::default();
    let a = vec![Polynomial::new(vec![]), Polynomial::new(vec![1, 2])];
    let b = vec![Polynomial::new(vec![3]), Polynomial::new(vec![4, 5])];
    let actual = module_lwe::utils::mul_vec_simple(&a, &b, params.q, &params.f, params.omega);
    assert_eq!(actual.coeffs(), &[4, 13, 10]);
}
