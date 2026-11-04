from oci_vcn_cidr_auditor import audit_network, load_export
r=audit_network(load_export('examples/network.json'),'network.json')
for f in r['findings']: print(f"{f['rule']} {f['severity']}: {f['message']} [{f['citation']}]")
assert {f['rule'] for f in r['findings']} == {'CIDR001','CIDR002','CIDR003','CIDR004','CIDR005'}
fixed={'vcns':[{'cidr':'10.0.0.0/16','subnets':[{'cidr':'10.0.1.0/24'}]}, {'cidr':'10.1.0.0/16','subnets':[]}]}
assert not audit_network(fixed)['findings']
print('DEMO OK: 5 seeded findings detected; corrected layout has 0 findings')
