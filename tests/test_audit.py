import unittest
from oci_vcn_cidr_auditor import audit_network, load_export

def v(c='10.0.0.0/24', subs=()):
    return {'cidr': c, 'subnets':[{'cidr':s} for s in subs]}
def rules(*vs):
    return [f['rule'] for f in audit_network({'vcns':list(vs)})['findings']]
class AuditTests(unittest.TestCase):
    def test_clean(self): self.assertEqual(rules(v(subs=['10.0.0.0/26'])), [])
    def test_outside(self): self.assertIn('CIDR001',rules(v(subs=['10.1.0.0/24'])))
    def test_overlap(self): self.assertIn('CIDR002',rules(v(subs=['10.0.0.0/25','10.0.0.0/26'])))
    def test_adjacent(self): self.assertNotIn('CIDR002',rules(v(subs=['10.0.0.0/26','10.0.0.64/26'])))
    def test_vcn_overlap(self): self.assertIn('CIDR003',rules(v(),v('10.0.0.0/25')))
    def test_vcn_disjoint(self): self.assertNotIn('CIDR003',rules(v(),v('10.1.0.0/24')))
    def test_invalid(self): self.assertIn('CIDR004',rules(v('bad')))
    def test_host_bits(self): self.assertIn('CIDR004',rules(v('10.0.0.1/24')))
    def test_ipv6(self): self.assertIn('CIDR004',rules(v('::/64')))
    def test_bad_subnets(self): self.assertIn('CIDR004',rules({'cidr':'10.0.0.0/24','subnets':7}))
    def test_bad_row(self): self.assertIn('CIDR004',rules(None))
    def test_pressure(self): self.assertIn('CIDR005',rules(v(subs=['10.0.0.0/24'])))
    def test_union_not_double_count(self): self.assertNotIn('CIDR005',rules(v(subs=['10.0.0.0/25','10.0.0.0/25'])))
    def test_outside_not_counted(self): self.assertNotIn('CIDR005',rules(v(subs=['10.1.0.0/16'])))
    def test_sample(self):
        r=audit_network(load_export('examples/network.json'))
        self.assertEqual(r['summary']['total'],5)
        self.assertTrue(all('#' in f['citation'] for f in r['findings']))
