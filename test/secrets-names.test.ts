// Reguła wp.secret.hardcoded: wartość w kształcie nazwy (opcja, klucz konfiguracji, ścieżka) nie jest sekretem,
// nawet gdy leży pod nazwą ze słowem secret, password albo token. Każdy przypadek ujemny ma dodatni odpowiednik,
// żeby poprawka nie zamieniła się w ślepotę. Wartości losowe są składane w teście z kawałków, to atrapy.
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/index';
import type { Finding } from '../src/index';

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function secrets(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-secname-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.secret.hardcoded');
}

// Atrapy do przypadków dodatnich.
const mixedCase = ['Zx9f', 'Q3mL', 'p7Tn', '2VbK'].join('');
const hexToken = ['a1b2c3d4', 'e5f6a7b8', 'c9d0e1f2', 'a3b4c5d6'].join('');
const wordsWithYear = ['admin', 'password', '2024'].join('_');
const licenseKey = ['AB12', 'CD34', 'EF56', 'GH78'].join('-');

describe('wartość w kształcie nazwy', () => {
  it('nazwa opcji w stałej to nie sekret', async () => {
    const f = await secrets(`<?php
define( 'ACME_SECRET_KEY', 'acme1_secret_key' );
define( 'ACME_AUTH_PASSWORD', 'acme1_auth_password' );`);
    expect(f).toHaveLength(0);
  });

  it('nazwa transientu i klucz konfiguracji w tablicy to nie sekret', async () => {
    const f = await secrets(`<?php
$map = array(
	'api_key_valid' => 'acme_check_licence_1',
	'secret'        => 'cdn.s3.secret',
);`);
    expect(f).toHaveLength(0);
  });

  it('ścieżka punktu końcowego to nie sekret', async () => {
    const f = await secrets(`<?php
$endpoints = array( 'OAUTH_TOKEN_ENDPOINT' => '/oauth2/v2.0/token' );`);
    expect(f).toHaveLength(0);
  });
});

describe('przypadki, które nadal są zgłaszane', () => {
  it('losowy token z dużymi i małymi literami', async () => {
    const f = await secrets(`<?php
define( 'ACME_SECRET', '${mixedCase}' );`);
    expect(f).toHaveLength(1);
  });

  it('losowy token szesnastkowy bez separatorów', async () => {
    const f = await secrets(`<?php
$api_key = '${hexToken}';`);
    expect(f).toHaveLength(1);
  });

  it('hasło z małych liter i słów, ale z rokiem', async () => {
    const f = await secrets(`<?php
$password = '${wordsWithYear}';`);
    expect(f).toHaveLength(1);
  });

  it('klucz licencyjny z dużych liter', async () => {
    const f = await secrets(`<?php
$secret = '${licenseKey}';`);
    expect(f).toHaveLength(1);
  });
});
