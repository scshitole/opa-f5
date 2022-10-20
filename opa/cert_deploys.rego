
package terraform.policies.cert_deploys

import input.plan as tfplan

deny[msg] {
  r := tfplan.resource_changes[_]
  r.type == "bigip_as3"
  cert := r.change.after.Sample_cert_02.A1.webcert1.certificate
  contains(cert, "BEGIN CERTIFICATE")
  msg := sprintf("You are exposing the Certificates in  AS3 %v", [cert])
}
