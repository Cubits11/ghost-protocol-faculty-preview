from s3_budget.accountant import ZCDPAccountant

def test_eps_monotone():
    acc = ZCDPAccountant(delta=1e-6)
    e0 = acc.eps()
    acc.add_rho(0.01)
    e1 = acc.eps()
    acc.add_rho(0.02)
    e2 = acc.eps()
    assert e0 <= e1 <= e2

def test_mi_bound():
    acc = ZCDPAccountant(delta=1e-6)
    acc.add_rho(0.1)
    mi = acc.mi_bound_bits()
    assert mi > 0
    assert mi < 1.0  # Should be small for rho=0.1
