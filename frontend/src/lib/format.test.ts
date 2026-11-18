import { describe, expect, it } from 'vitest';

import { asSystem, kindOf } from './model';
import {
  authorityText, codeRef, count, endpointText, fieldIdText, fullCodeRef, kindTitle, methodKey, payload, requirementText,
  shortClass, shortNames, shortRoute,
} from './format';
import type { AuthoritySource, Requirement } from './types';
import { commonPrefix, groupBy } from './utils';

describe('requirementText', () => {
  it('writes nested requirements with parentheses', () => {
    expect(requirementText({ kind: 'AND', operands: [{ kind: 'AUTHENTICATED' },
      { kind: 'OR', operands: [{ kind: 'ANY_AUTHORITY', authorities: ['A'] }, { kind: 'ANY_AUTHORITY', authorities: ['B'] }] }] }))
      .toBe('authenticated and (A or B)');
    expect(requirementText(undefined)).toBe('none');
  });
});

describe('names', () => {
  it('shortens qualified names in running text', () => {
    expect(shortNames('dev.crain.employeeservice.employee.Employee#getSalary() is skipped')).toBe('Employee#getSalary() is skipped');
    expect(shortRoute('GRPC', 'fixtures.grpc.Greeter/SayHello')).toBe('Greeter/SayHello');
    expect(codeRef({ className: 'a.b.Outer$Inner', method: 'find(long)', line: 3 })).toBe('Outer.Inner#find:3');
    expect(endpointText({ httpMethod: 'GET', route: '/x', params: 'a=b' })).toBe('GET /x?a=b');
    expect(fieldIdText('employee-service/field:dev.crain.Employee.ssn')).toBe('employee-service Employee.ssn');
    expect(commonPrefix(['/owners', '/owners/{id}'])).toBe('/owners');
  });
});

describe('documents', () => {
  it('tells graphs and diff reports apart', () => {
    expect(kindOf({ services: [] })).toBe('system');
    expect(kindOf({ nodes: [] })).toBe('application');
    expect(kindOf({ changes: [] })).toBe('diff');
    expect(kindOf({})).toBeNull();
    const app = { schemaVersion: 1, service: 'a', revision: 'r', nodes: [], edges: [], flows: [], findings: [] };
    expect(asSystem(app).services).toEqual([app]);
  });
});

describe('codeRef', () => {
  it('keeps a bare method name whole', () => {
    expect(codeRef({ className: 'a.OwnerRepository', method: 'findAll' })).toBe('OwnerRepository#findAll');
    expect(codeRef({ className: 'a.Owners', method: 'find(long)', line: 7 })).toBe('Owners#find:7');
  });
});

describe('authorityText', () => {
  it('names the source and its freshness, and nothing when the graph has none', () => {
    expect(authorityText({ kind: 'JWT_CLAIMS', freshness: 'SNAPSHOT' })).toMatch(/^Authorities from JWT claims; snapshot: /);
    expect(authorityText(undefined)).toBe('');
  });
});

describe('groupBy', () => {
  it('keeps each group in the items\' order', () => {
    expect([...groupBy(['a1', 'b1', 'a2'], item => item[0])]).toEqual([['a', ['a1', 'a2']], ['b', ['b1']]]);
  });
});

describe('requirementText of every kind', () => {
  it('names the kinds the server writes, and the expression or the kind for the rest', () => {
    expect(['PERMIT_ALL', 'AUTHENTICATED', 'FULLY_AUTHENTICATED', 'REMEMBER_ME', 'ANONYMOUS', 'DENY_ALL'].map(kind =>
      requirementText({ kind: kind as Requirement['kind'] }))).toEqual(['permitAll', 'authenticated', 'fullyAuthenticated',
      'rememberMe', 'anonymous', 'denyAll']);
    expect(requirementText({ kind: 'ALL_AUTHORITIES', authorities: ['A', 'B'] })).toBe('A and B');
    expect(requirementText({ kind: 'EXPRESSION', expression: '@authz.canRead(#id)',
      decidedBy: { className: 'com.example.Authz', method: 'canRead(java.lang.Long)' } }))
      .toBe('@authz.canRead(#id) (decided by Authz#canRead)');
    expect(requirementText({ kind: 'ANY_AUTHORITY' })).toBe('');
    expect(requirementText({ kind: 'NOT', operands: [{ kind: 'ANY_AUTHORITY', authorities: ['A', 'B'] }] }))
      .toBe('not (A or B)');
    expect(requirementText({ kind: 'EXPRESSION', expression: '@guard.check(#id)' })).toBe('@guard.check(#id)');
    expect(requirementText({ kind: 'SOMETHING_NEWER' as Requirement['kind'] })).toBe('SOMETHING_NEWER');
  });
});

describe('text helpers', () => {
  it('shorten class names, and say nothing for none', () => {
    expect(shortClass('dev.crain.profileservice.admin.CompensationController$CompensationView'))
      .toBe('CompensationController.CompensationView');
    expect(shortClass(undefined)).toBe('');
    expect(shortNames(null)).toBe('');
    expect(shortNames(undefined)).toBe('');
  });

  it('write a kind as a title', () => {
    expect(kindTitle('BYPASSED')).toBe('Bypassed');
    expect(kindTitle('DIAGONAL_ESCALATION')).toBe('Diagonal escalation');
  });

  it('keep a route that is no gRPC method whole; a gRPC rule with no route reads empty', () => {
    expect(shortRoute('GET', 'fixtures.grpc.Greeter/SayHello')).toBe('fixtures.grpc.Greeter/SayHello');
    expect(shortRoute('GRPC', undefined)).toBe('');
    expect(endpointText({ httpMethod: 'POST', route: '/x' })).toBe('POST /x');
  });

  it('write code references short, by method key, and in full', () => {
    expect(codeRef(undefined)).toBe('');
    expect(codeRef({ className: 'a.Owners' })).toBe('Owners');
    expect(methodKey('dev.crain.Foo#find(long)')).toBe('Foo#find');
    expect(methodKey('dev.crain.Foo')).toBe('Foo');
    expect(fullCodeRef({ className: 'a.Owners', method: 'find(long)', line: 7 })).toBe('a.Owners#find(long), line 7');
    expect(fullCodeRef({ className: 'a.Owners' })).toBe('a.Owners');
    expect(fullCodeRef(undefined)).toBe('');
  });

  it('write a payload as its class, a collection with brackets', () => {
    expect(payload({ type: 'x.Owner', many: true })).toBe('Owner[]');
    expect(payload({ type: 'x.Owner', many: false })).toBe('Owner');
    expect(payload(undefined)).toBe('');
  });

  it('write a view\'s field as the model path its template reads', () => {
    expect(fieldIdText('a/field:view:owners/details.owner:pets[]:name')).toBe('a owners/details: owner.pets[].name');
    expect(fieldIdText('a/field:x.Outer$Inner.name')).toBe('a Inner.name');
  });

  it('count in the singular for one only', () => {
    expect(count(1, 'check')).toBe('1 check');
    expect(count(0, 'check')).toBe('0 checks');
    expect(count(2, 'entry', 'entries')).toBe('2 entries');
  });
});

describe('authorityText of every source', () => {
  it('prefers the graph\'s own detail, and falls back to the kind\'s name and unknown freshness', () => {
    expect(authorityText({ kind: 'USER_DETAILS', freshness: 'LIVE', detail: 'JdbcUserDetailsManager' }))
      .toBe('Authorities from JdbcUserDetailsManager; live: re-read on every request: a revocation is honored on the'
        + ' next check');
    expect(authorityText({ kind: 'SAML' } as AuthoritySource)).toBe('Authorities from SAML; unknown: unknown');
    expect(authorityText({ kind: 'JWT_CLAIMS', freshness: 'LATER' as AuthoritySource['freshness'] }))
      .toBe('Authorities from JWT claims; later: ');
  });
});
