import { afterAll, describe, expect, it } from 'vitest';
import { audit, cleanupTempDirs, copyNamedFixture, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

const firestore = (body: string) =>
  `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n${body}\n  }\n}\n`;

async function findingsFor(files: Record<string, string>) {
  const root = makeTempDir();
  writeFiles(root, files);
  return (await audit(root)).findings.filter((f) => f.ruleId === 'firebase-rules');
}

describe('fixtures/firebase', () => {
  it('reports open writes, global reads and test-mode rules', async () => {
    const result = await audit(copyNamedFixture('firebase'));
    const got = result.findings.map(
      (f) => `${f.severity} ${f.messageId} ${f.params.service} ${f.params.path} @ ${f.file}:${f.line}`,
    );
    expect(got).toEqual([
      'critical firebase.openWrite Realtime Database / @ database.rules.json:4',
      'critical firebase.openWrite Firestore /{document=**} @ firestore.rules:6',
      'critical firebase.openWrite Firestore /messages/{messageId} @ firestore.rules:9',
      'critical firebase.openWrite Firestore /orders/{orderId} @ firestore.rules:12',
      'high firebase.openRead Firestore /{document=**} @ apps/admin/firestore.rules:5',
      'high firebase.openRead Realtime Database / @ database.rules.json:3',
      'high firebase.testMode Cloud Storage /{allPaths=**} @ storage.rules:5',
    ]);
  });
});

describe('firebase-rules false positives', () => {
  it('accepts public reads on a given collection and real conditions', async () => {
    expect(
      await findingsFor({
        'firestore.rules': firestore(`
    function signedIn() { return request.auth != null; }
    match /products/{id} { allow read: if true; allow get, list; }
    match /users/{uid} { allow read, write: if signedIn() && request.auth.uid == uid; }
    match /flags/{id} { allow write: if true == false; }
    match /{document=**} { allow read, write: if false; }`),
      }),
    ).toEqual([]);
  });

  it('ignores commented-out rules and strings', async () => {
    expect(
      await findingsFor({
        'firestore.rules': firestore(`
    // allow read, write: if true;
    /* match /{document=**} { allow write; } */
    match /a/{id} { allow read: if resource.data.label == 'allow write;'; }`),
      }),
    ).toEqual([]);
  });

  it('ignores .rules files that are not Firebase rules', async () => {
    expect(await findingsFor({ 'lint.rules': 'allow write;\n' })).toEqual([]);
  });

  it('only flags root-level reads in Realtime Database rules', async () => {
    expect(
      await findingsFor({
        'database.rules.json': JSON.stringify({
          rules: { public: { '.read': true }, users: { $uid: { '.write': 'auth.uid === $uid' } } },
        }),
      }),
    ).toEqual([]);
    expect(await findingsFor({ 'database.rules.json': '{ not json' })).toEqual([]);
  });
});
