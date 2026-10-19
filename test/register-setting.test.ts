// Reguła wp.option.no_sanitize_callback: trzeci argument jako callable w tablicy [obiekt, metoda].
// WordPress zamienia taki argument na array( 'sanitize_callback' => $callable ), więc to nie jest brak sanitizacji.
// Każdy przypadek ujemny ma dodatni odpowiednik, żeby poprawka nie zamieniła się w ślepotę.
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

async function option(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-regset-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.option.no_sanitize_callback');
}

describe('callable w tablicy jako trzeci argument', () => {
  it('[ $this, metoda ] i array( __CLASS__, metoda ) nie są brakiem sanitize_callback', async () => {
    const f = await option(`<?php
class Settings {
	public function init() {
		register_setting( 'grp', 'opt_a', [ $this, 'sanitize_a' ] );
		register_setting( 'grp', 'opt_b', array( $this, 'sanitize_b' ) );
		register_setting( 'grp', 'opt_c', array( __CLASS__, 'sanitize_c' ) );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('nazwa klasy, self::class, static::class i new też są callable', async () => {
    const f = await option(`<?php
register_setting( 'grp', 'opt_a', array( 'My_Plugin_Settings', 'sanitize' ) );
register_setting( 'grp', 'opt_b', [ self::class, 'sanitize' ] );
register_setting( 'grp', 'opt_c', [ static::class, 'sanitize' ] );
register_setting( 'grp', 'opt_d', [ new Sanitizer(), 'run' ] );`);
    expect(f).toHaveLength(0);
  });
});

describe('przypadki, które nadal są zgłaszane', () => {
  it('tablica argumentów z kluczami, ale bez sanitize_callback', async () => {
    const f = await option(`<?php
register_setting( 'grp', 'opt_a', array( 'type' => 'string', 'default' => '' ) );
register_setting( 'grp', 'opt_b', [ 'type' => 'string', 'show_in_rest' => true ] );`);
    expect(f).toHaveLength(2);
  });

  it('tablica z jednym albo trzema elementami bez klucza nie jest callable', async () => {
    const f = await option(`<?php
register_setting( 'grp', 'opt_a', array( 'sanitize' ) );
register_setting( 'grp', 'opt_b', [ $this, 'sanitize', 'extra' ] );`);
    expect(f).toHaveLength(2);
  });

  it('brak trzeciego argumentu', async () => {
    const f = await option(`<?php
register_setting( 'grp', 'opt_a' );`);
    expect(f).toHaveLength(1);
  });

  it('tablica z sanitize_callback i callable w kluczu nadal przechodzi', async () => {
    const f = await option(`<?php
register_setting( 'grp', 'opt_a', array( 'sanitize_callback' => [ $this, 'sanitize' ] ) );
register_setting( 'grp', 'opt_b', array( 'type' => 'string', 'sanitize_callback' => 'sanitize_text_field' ) );`);
    expect(f).toHaveLength(0);
  });
});
