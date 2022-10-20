package terraform.policies.cert_deploys

import input.plan as tfplan

deny[msg] {
  cert := tfplan.planned_values.root_module.resources[_].values.as3_json
  contains(cert, "BEGIN CERTIFICATE") 
  msg := sprintf("You are exposing the Certificates in  AS3 %v", [cert])
}
