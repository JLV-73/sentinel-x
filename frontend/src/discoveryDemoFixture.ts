// Entirely fictional laboratory output, embedded in the application; never a target.
const limits = ['caller_declared_provenance','effective_route_declared_by_caller','response_headers_only','method_unknown','positional_route_labels','no_vulnerability_or_compliance_conclusion'];
export const discoveryDemoFixture = {
 pages:0, requests:1, bytes:100, complete:false, reason:'http_refused',
 graph:{pages:[],relations:[],resources:[]},
 intelligence:{schema_version:'fortress.discovery-intelligence/1',limits,pages:[{
  route:'page-1', observed_at:'2026-01-01T00:00:00+00:00', status:403,
  state:'access_denied', method:'unknown', provenance:{kind:'caller_declared',attestation:'none'},
  confidence:'not_evaluated', observations:null, findings:[], limits, graph_route:'route-'+ 'a'.repeat(64)
 }]}
};
