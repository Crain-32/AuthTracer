import { Model } from '@/lib/model';
import type { ApplicationGraph, EgressNode, Exposure, Flow, IngressNode, LocationNode, SystemGraph } from '@/lib/types';

import { app, endpoint, field, ingress, link } from './graphs';

const profiles: IngressNode = { type: 'ingress', id: 'ingress:GET /profiles/{id}', httpMethod: 'GET', route: '/profiles/{id}',
  handler: { className: 'dev.crain.profileservice.ProfileController', method: 'get(long)', line: 18 },
  response: { type: 'dev.crain.profileservice.ProfileView', many: false } };

const employees: EgressNode = { type: 'egress', id: 'egress:employees', client: 'RestClient', httpMethod: 'GET',
  uriTemplate: '/employees/{id}', baseUrl: 'http://employee-service', credentials: 'RELAY',
  callSite: { className: 'dev.crain.profileservice.Employees', method: 'find(long)', line: 40 } };

const jwks: EgressNode = { type: 'egress', id: 'egress:jwks', client: 'NimbusJwtDecoder', httpMethod: 'GET',
  uriTemplate: '/oauth2/jwks' };

const rule: LocationNode = { type: 'location', id: 'location:rule', mechanism: 'authorizeHttpRequests', scope: 'HTTP_REQUEST',
  phase: 'PRE', routePattern: '/profiles/**', requirement: { kind: 'ANY_AUTHORITY', authorities: ['SCOPE_profiles.read'] },
  target: { className: 'dev.crain.profileservice.SecurityConfig', method: 'filterChain(HttpSecurity)', line: 20 } };

const preAuthorize: LocationNode = { type: 'location', id: 'location:profiles', mechanism: '@PreAuthorize', scope: 'METHOD',
  phase: 'PRE', requirement: { kind: 'ANY_AUTHORITY', authorities: ['ROLE_USER'] }, proxied: true,
  target: { className: 'dev.crain.profileservice.ProfileService', method: 'find(long)', line: 31 } };

const mask: LocationNode = { type: 'location', id: 'location:ssn', mechanism: '@PreAuthorize', scope: 'FIELD', phase: 'PRE',
  field: 'ssn', requirement: { kind: 'ANY_AUTHORITY', authorities: ['ROLE_ADMIN'] },
  denial: { kind: 'HANDLER', handler: 'SsnMask' }, target: { className: 'dev.crain.employeeservice.Employee', method: 'getSsn()' } };

/**
 * profile-service's GET /profiles/{id} checks a request rule and a method check, then calls employee-service's GET /employees/{id},
 * whose Employee.ssn has a field check that masks it. profile-service also has two Actuator endpoints with nothing on their
 * path, and fetches its token keys outside any request.
 */
export function linkedSystem(): { system: SystemGraph; exposures: Exposure[] } {
  const profileService: ApplicationGraph = {
    ...app('profile-service', [profiles, ingress('/actuator/health'), ingress('/actuator/info'), rule, preAuthorize, employees,
      jwks, field('dev.crain.profileservice.ProfileView', 'ssn'), field('dev.crain.profileservice.ProfileView', 'name'),
    ], { 'ingress:GET /profiles/{id}': ['location:rule', 'location:profiles', 'egress:employees'] }),
    authoritySource: { kind: 'JWT_CLAIMS', freshness: 'SNAPSHOT' },
    findings: [
      { kind: 'OPEN_SENSITIVE_ENDPOINT', message: 'Actuator heapdump (GET /actuator/heapdump) answers anyone',
        location: { className: 'org.springframework.boot.actuate.management.HeapDumpWebEndpoint' } },
      { kind: 'BYPASSED', message: 'dev.crain.profileservice.ProfileService#audit(long) is called on this, skipping its check',
        location: { className: 'dev.crain.profileservice.ProfileService', method: 'find(long)', line: 33 } },
      { kind: 'BYPASSED', message: 'dev.crain.profileservice.ProfileService#export(long) is called on this, skipping its check',
        location: { className: 'dev.crain.profileservice.ProfileService', method: 'list()', line: 52 } },
    ],
  };
  const employeeService: ApplicationGraph = {
    ...app('employee-service', [ingress('/employees/{id}'), mask,
      field('dev.crain.employeeservice.Employee', 'ssn', { labels: ['PII'], javaType: 'java.lang.String' }),
      field('dev.crain.employeeservice.Employee', 'name')], { 'ingress:GET /employees/{id}': ['location:ssn'] }),
    authoritySource: { kind: 'JWT_CLAIMS', freshness: 'SNAPSHOT' },
  };
  const call = link('profile-service/egress:employees', 'employee-service/ingress:GET /employees/{id}', 'NETWORK_OBSERVED');
  const system: SystemGraph = {
    schemaVersion: 1, services: [profileService, employeeService], links: [call], flows: [], identities: [],
    observations: [
      { subject: 'profile-service/egress:employees -> employee-service/ingress:GET /employees/{id}', kind: 'LINK', count: 5, granted: 0,
        denied: 0 },
      { subject: 'profile-service/location:profiles', kind: 'LOCATION', count: 5, granted: 4, denied: 1 },
    ],
    findings: [{ kind: 'UNMATCHED_CALL', message: 'A traced call GET /legacy matches no ingress' }],
  };
  const network = (name: string): Flow => ({ path: 'profile-service/egress:employees', from: `employee-service/field:dev.crain.employeeservice.Employee.${name}`,
    to: `profile-service/field:dev.crain.profileservice.ProfileView.${name}`, source: 'DIRECT', kind: 'NETWORK' });
  const steps = [
    { location: 'profile-service/location:rule', mechanism: 'authorizeHttpRequests', requirement: 'SCOPE_profiles.read' },
    { location: 'profile-service/location:profiles', mechanism: '@PreAuthorize', requirement: 'ROLE_USER' },
  ];
  const profileField = (name: string, more: Partial<Exposure>): Exposure => ({
    ...endpoint('profile-service', '/profiles/{id}', 'SCOPE_profiles.read and ROLE_USER', name),
    fieldId: `profile-service/field:dev.crain.profileservice.ProfileView.${name}`, steps,
    sources: [`employee-service/field:dev.crain.employeeservice.Employee.${name}`], lineage: [network(name)], ...more });
  const exposures: Exposure[] = [
    { ...endpoint('profile-service', '/profiles/{id}', 'SCOPE_profiles.read and ROLE_USER'), steps },
    profileField('name', {}),
    profileField('ssn', { requirement: 'SCOPE_profiles.read and ROLE_USER and ROLE_ADMIN', adds: 'ROLE_ADMIN',
      labels: ['PII'], steps: [...steps, { location: 'employee-service/location:ssn', mechanism: '@PreAuthorize',
        requirement: 'ROLE_ADMIN', guards: 'employee-service/field:dev.crain.employeeservice.Employee.ssn' }] }),
    endpoint('profile-service', '/actuator/health', 'none'),
    endpoint('profile-service', '/actuator/info', 'none'),
    endpoint('employee-service', '/employees/{id}', 'authenticated'),
  ];
  return { system, exposures };
}

export function linkedModel(origin = 'Latest stored system graph'): Model {
  const { system, exposures } = linkedSystem();
  return new Model(system, exposures, origin);
}
